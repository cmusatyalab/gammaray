#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "deep_inspection.h"
#include "ntfs.h"
#include "redis_queue.h"
#include "xray_ntfs_fs.h"

static uint64_t partition_offset = 0;
static uint64_t cluster_size = 0;
static uint64_t file_record_size = 0;
static struct kv_store* handle;
static int fd_disk;

static int64_t xrayfs_pathlookup(const char* path)
{
    int64_t inode = -ENOENT;
    if (redis_path_get(handle, (const uint8_t *) path,
                       strnlen(path, (size_t) 4096), (uint64_t *) &inode))
        return -ENOENT;
    return inode;
}

static int xrayfs_ntfs_getattr(const char* path, struct stat* stbuf)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t data[file_record_size];
    size_t len2 = file_record_size;
    struct ntfs_file_name fdata;
    struct ntfs_file_record rec;

    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "inode",
                             (uint8_t*) &data, &len2))
        return -ENOENT;

    if (ntfs_get_attribute(data, &fdata, NTFS_FILE_NAME))
        return -ENOENT;

    rec = *((struct ntfs_file_record *) data);

    memset(stbuf, 0, sizeof(struct stat));

    if (rec.flags & 0x02)
        stbuf->st_mode |= S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH;
    else
        stbuf->st_mode |= S_IFREG;

    if (fdata.flags & 0x0001)
        stbuf->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
    else
        stbuf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;

    stbuf->st_nlink = rec.hard_link_count;
    stbuf->st_blksize = cluster_size;
    stbuf->st_size = fdata.real_size; 
    stbuf->st_blocks = (stbuf->st_size % 512) ? stbuf->st_size / 512 + 1 : 
                                                stbuf->st_size / 512;
    stbuf->st_atime = fdata.r_time;
    stbuf->st_mtime = fdata.a_time;
    stbuf->st_ctime = fdata.m_time;

    return 0;
}

/**
 * Instead of ext4_dir_entry we need to walk INDEX RECORDS one level deep (?)
 *
 */
static int xrayfs_ntfs_readdir(const char* path, void* buf,
                               fuse_fill_dir_t filler, off_t offset,
                               struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t data_buf[cluster_size], **list;
    size_t len = 0, len2 = 0;
    uint64_t position = 0, sector = 0, i = 0;
    struct ext4_dir_entry dir;

    if (inode_num < 0)
        return -ENOENT;

    if (redis_list_get(handle, REDIS_FILE_SECTORS_LGET,
                       inode_num, &list, &len))
        return -ENOENT;

    for (i = 0; i < len; i++)
    {
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &sector);
        len2 = cluster_size;

        if (redis_hash_field_get(handle, REDIS_DIR_SECTOR_GET, sector, "data",
                                 data_buf, &len2))
            return -ENOENT;

        position = 0;
        /* loop through all dentry in block while (position < cluster_size) */
        while (position < cluster_size)
        {
            if (ext4_read_dir_entry(&data_buf[position], &dir))
                return -ENOENT;
            
            if (dir.inode == 0)
            {
                if (dir.rec_len)
                {
                    position += dir.rec_len;
                    continue;
                }
            }

            dir.name[dir.name_len] = 0;
            filler(buf, (const char*) dir.name, NULL, 0);
            position += dir.rec_len;
        }
    }

    redis_free_list(list, len);

    return 0;
}

static int xrayfs_ntfs_open(const char* path, struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);

    if (inode_num < 0)
        return -ENOENT;

    if ((fi->flags & 3) != O_RDONLY)
        return -EROFS;

    return 0;
}

static int xrayfs_ntfs_read(const char* path, char* buf, size_t size,
                            off_t offset, struct fuse_file_info* fi)
{
    uint64_t inode_num = xrayfs_pathlookup(path);
    uint8_t** list;
    size_t len = 0;
    ssize_t readb = 0, toread = 0, ret = 0;
    uint64_t position = 0, sector = 0, i = 0;
    struct stat st;
    int64_t start = offset / 4096, end;

    if (xrayfs_ntfs_getattr(path, &st))
        return -ENOENT;

    if (offset > st.st_size)
        return -EINVAL;

    if (offset + size > st.st_size)
        size = st.st_size - offset;

    end = start + ((size + 4095) / 4096);

    if (redis_list_get_var(handle, REDIS_FILE_SECTORS_LGET_VAR,
                           inode_num, &list, &len, start, end))
        return -ENOENT;

    /* loop through all blocks of file to size */
    for (i = 0; i < len; i++)
    {
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &sector);

        lseek(fd_disk, sector * 512 + offset % cluster_size, SEEK_SET);
        readb = 0;

        if (position + cluster_size - offset % cluster_size < size)
            toread = cluster_size - offset % cluster_size;
        else
            toread = size - position;

        while (readb < toread)
        {
            ret = read(fd_disk, (char*) &(buf[position]), toread - readb);
            if (ret < 0)
                return -EINVAL;
            readb += ret;
        }

        offset += readb;
        position += readb;
    }

    redis_free_list(list, len);

    return position;
}

int main(int argc, char* argv[])
{
    struct ntfs_boot_file bootf;
    const char* path = argv[argc - 1];
    handle = redis_init("4", false);
    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    fd_disk = open(path, O_RDONLY);
    argc -= 1;

    if (qemu_get_bootf(handle, &bootf, (uint64_t) 0))
        return EXIT_FAILURE;

    cluster_size = bootf.bytes_per_sector * bootf.sectors_per_cluster;
    file_record_size = ntfs_file_record_size(&bootf);

    if (qemu_get_pt_offset(handle, &partition_offset, (uint64_t) 0))
        return EXIT_FAILURE;

    return fuse_main(argc, argv, &xrayfs_ntfs_oper, NULL);
}
