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
#include "util.h"

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
    struct ntfs_standard_attribute_header sah;
    struct ntfs_file_record rec;
    struct ntfs_file_name fdata;
    uint64_t fsize = 0, data_offset = 0;

    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "inode",
                             (uint8_t*) &data, &len2))
        return -ENOENT;

    //hexdump(data, len2);
    rec = *((struct ntfs_file_record *) data);
  
    if (ntfs_get_attribute(data, &fdata, &data_offset, NTFS_FILE_NAME))
        return -ENOENT;  

    data_offset = 0;

    if (!((rec.flags & 0x02) == 0x02))
    {
        if (ntfs_get_attribute(data, &sah, &data_offset, NTFS_DATA))
            return -ENOENT;

        ntfs_get_size(data, &sah, &data_offset, &fsize);
    }

    memset(stbuf, 0, sizeof(struct stat));

    if ((rec.flags & 0x02) == 0x02)
        stbuf->st_mode |= S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH;
    else
        stbuf->st_mode |= S_IFREG;

    if (fdata.flags & 0x0001)
        stbuf->st_mode |= S_IRUSR | S_IRGRP | S_IROTH;
    else
        stbuf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;

    stbuf->st_nlink = rec.hard_link_count;
    stbuf->st_blksize = cluster_size;
    stbuf->st_size = fsize; 
    stbuf->st_blocks = (stbuf->st_size % 512) ? stbuf->st_size / 512 + 1 : 
                                                stbuf->st_size / 512;
    stbuf->st_atime = fdata.r_time;
    stbuf->st_mtime = fdata.a_time;
    stbuf->st_ctime = fdata.m_time;

    return 0;
}

static int xrayfs_ntfs_readdir(const char* path, void* buf,
                               fuse_fill_dir_t filler, off_t offset,
                               struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t data_buf[cluster_size], **list;
    size_t len = 0, len2 = 0;
    uint64_t position = 0, sector = 0, i = 0;
    struct ntfs_index_record_entry ire;
    char* utf16_fname;
    size_t utf16_fname_size;
    size_t current_fname_size = 512;
    char* current_fname = malloc(current_fname_size);
    uint32_t counter = 0;
    struct ntfs_index_record_header irh;

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
        fprintf(stdout, "sector: %"PRIu64" size=%"PRIu64"\n", sector, len2);

        if (redis_hash_field_get(handle, REDIS_DIR_SECTOR_GET, sector, "data",
                                 data_buf, &len2))
            return -ENOENT;

        fprintf(stdout, "sector: %"PRIu64" size=%"PRIu64"\n", sector, len2);
        position = 0;
        hexdump(data_buf, 128);
        irh = *((struct ntfs_index_record_header*) data_buf);
        position = irh.offset_to_index_entries + 0x18;
        /* walk all entries */
        while (!(ire.flags & 0x02) && counter++ < 20)
        {
            /* read index entries */
            hexdump(&(data_buf[position]), 128);
            ntfs_read_index_record_entry(data_buf, &position, &ire);
            fprintf(stdout, "xray_ntfs_fs: walking index record entry...\n");

            if (ntfs_get_reference_int(&(ire.ref)) < 15 ||
                ntfs_get_reference_int(&(ire.parent)) == ntfs_get_reference_int(&(ire.ref)))
            {
                position += ire.size - sizeof(struct ntfs_index_record_entry);
                fprintf(stdout, "xray_ntfs_fs: ignoring entry... ire.ref = %"PRIu64"\n", ntfs_get_reference_int(&(ire.ref)));
                fprintf(stdout, "xray_ntfs_fs: ignoring entry... ire.parent = %"PRIu64"\n", ntfs_get_reference_int(&(ire.parent)));
                continue;
            }

            utf16_fname = (char*) &(data_buf[position]);
            utf16_fname_size = ire.filename_length * 2;
            memset(current_fname, 0, current_fname_size);
            ntfs_utf16_to_char(utf16_fname, utf16_fname_size,
                               (char*) current_fname, current_fname_size);

            position += ire.size - sizeof(struct ntfs_index_record_entry);
            fprintf(stdout, "new entry: %s\n", current_fname);

            if (ntfs_get_reference_int(&(ire.ref)))
            {
                filler(buf, current_fname, NULL, 0);
                fprintf(stdout, "added new entry!\n");
            }
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
    uint64_t position = 0, i = 0;
    int64_t sector = 0;
    struct stat st;
    int64_t start = offset / cluster_size, end;
    uint64_t file_record_offset = 0;
    struct ntfs_standard_attribute_header sah;
    uint8_t data[file_record_size];
    size_t len2 = file_record_size;
    ssize_t readb = 0, toread = 0, ret = 0;


    if (xrayfs_ntfs_getattr(path, &st))
        return -ENOENT;

    if (offset > st.st_size)
        return -EINVAL;

    if (offset + size > st.st_size)
        size = st.st_size - offset;

    end = start + ((size + cluster_size - 1) / cluster_size);

    if (redis_list_get_var(handle, REDIS_FILE_SECTORS_LGET_VAR,
                           inode_num, &list, &len, start, end))
        return -ENOENT;

    if (len < end - start)
        return -EINTR;

    /* loop through all blocks of file to size */
    for (i = 0; i < len; i++)
    {
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNd64, &sector);

        if (sector == -1)
        {
            /* read wholly contained within FILE record */
            if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "inode",
                                     (uint8_t*) &data, &len2))
                return -ENOENT;

            if (ntfs_get_attribute(data, &sah, &file_record_offset, NTFS_DATA))
                return -ENOENT;

            file_record_offset += sah.offset_of_attribute - sizeof(sah);
            memcpy(buf, &(data[file_record_offset + offset]), size);
            position = size;

            break;
        }
        else
        {
            lseek(fd_disk, sector * 512 + offset % cluster_size, SEEK_SET);
            readb = 0;

            if (position + cluster_size - offset % cluster_size < size)
                toread = cluster_size - offset % cluster_size;
            else
                toread = size - position;
            
            if (toread <= 0)
                break;

            while (readb < toread)
            {
                ret = read(fd_disk, (char*) &(buf[position]), toread - readb);
                if (ret < 0)
                {
                    fprintf(stdout, "system read failed\n");
                    return -EINVAL;
                }
                readb += ret;
            }

            offset += readb;
            position += readb;
        }
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
    if (fd_disk < 0)
    {
        fprintf_light_red(stderr, "Failed opening path: %s\n", path);
        return EXIT_FAILURE;
    }

    argc -= 1;

    if (qemu_get_bootf(handle, &bootf, (uint64_t) 1))
        return EXIT_FAILURE;

    cluster_size = bootf.bytes_per_sector * bootf.sectors_per_cluster;
    file_record_size = ntfs_file_record_size(&bootf);
    fprintf(stdout, "CLUSTER_SIZE == %"PRIu64"\n", cluster_size);
    fprintf(stdout, "FILE_RECORD_SIZE == %"PRIu64"\n", file_record_size);
    assert(cluster_size == 4096 && file_record_size == 1024);


    if (qemu_get_pt_offset(handle, &partition_offset, (uint64_t) 1))
        return EXIT_FAILURE;

    return fuse_main(argc, argv, &xrayfs_ntfs_oper, NULL);
}
