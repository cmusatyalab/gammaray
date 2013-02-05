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
#include "redis_queue.h"
#include "xray_fs.h"

static uint64_t partition_offset;
static uint64_t block_size;
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

static int xrayfs_getattr(const char* path, struct stat* stbuf)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    struct ext4_inode inode;
    size_t len2 = sizeof(struct ext4_inode);

    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "inode",
                             (uint8_t*) &inode, &len2))
        return -ENOENT;

    memset(stbuf, 0, sizeof(struct stat));

    stbuf->st_mode = inode.i_mode;
    stbuf->st_nlink = inode.i_links_count;
    stbuf->st_uid = inode.i_uid;
    stbuf->st_gid = inode.i_gid;
    stbuf->st_blksize = block_size;
    stbuf->st_size = ext4_file_size(inode);
    stbuf->st_blocks = (stbuf->st_size % 512) ? stbuf->st_size / 512 + 1 : 
                                                stbuf->st_size / 512;
    stbuf->st_atime = inode.i_atime;
    stbuf->st_mtime = inode.i_mtime;
    stbuf->st_ctime = inode.i_ctime;

    return 0;
}

static int xrayfs_readlink(const char* path, char* buf, size_t bufsize)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    ssize_t ret = 0;
    uint64_t position = 0, sector = 0;
    struct ext4_inode inode;
    size_t len2 = sizeof(struct ext4_inode);
    uint8_t** list = NULL;

    memset(buf, 0, bufsize);

    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "inode",
                             (uint8_t*) &inode, &len2))
        return -ENOENT;

    if (bufsize == ext4_file_size(inode))
        bufsize -= 1;

    if (ext4_file_size(inode) < bufsize)
        bufsize = ext4_file_size(inode);

    if (bufsize >= 4096)
        return -EINVAL;

    if (bufsize < 60)
    {
        memcpy(buf, (uint8_t*) inode.i_block, bufsize);
    }
    else
    {
        if (redis_list_get_var(handle, REDIS_FILE_SECTORS_LGET_VAR,
                               inode_num, &list, &len2, 0, 0))
            return -ENOENT;

        if (len2 <= 0)
            return -ENOENT;

        strtok((char*) (list)[0], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &sector);
        lseek(fd_disk, sector * 512, SEEK_SET);

        while (bufsize - position > 0)
        {
            ret = read(fd_disk, &(buf[position]), bufsize - position);
            if (ret < 0)
                return -ENOENT;
            position += ret;
        }
    }

    buf[bufsize] = 0;

    redis_free_list(list, len2);

    return 0;

}

static int xrayfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t data_buf[block_size];
    uint8_t** list;
    size_t len = 0, len2 = 0;
    uint64_t position = 0, sector = 0, i = 0;
    struct ext4_dir_entry dir;

    if (inode_num < 0)
        return -ENOENT;

    if (redis_list_get(handle, REDIS_FILE_SECTORS_LGET,
                       inode_num, &list, &len))
        return -ENOENT;

    /* loop through all blocks of dir file */
    for (i = 0; i < len; i++)
    {
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &sector);
        len2 = block_size;

        if (redis_hash_field_get(handle, REDIS_DIR_SECTOR_GET, sector, "data",
                                 data_buf, &len2))
            return -ENOENT;

        position = 0;
        /* loop through all dentry in block while (position < block_size) */
        while (position < block_size)
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

static int xrayfs_open(const char* path, struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);

    if (inode_num < 0)
        return -ENOENT;

    if ((fi->flags & 3) != O_RDONLY)
        return -EROFS;

    return 0;
}

/**
 *  This function must implement the following:
 *      (1) Lookup path from '/' recursively in Redis (dentries)
 *      (2) If path doesn't exist, return -ENOENT
 *      (3) Get list of block size sectors from 'filesectors:ID x y'
 *      (4) for each block, split on ':', read from disk (+partition offset)
 *      (5) Return 0
 */
static int xrayfs_read(const char* path, char* buf, size_t size, off_t offset,
                       struct fuse_file_info* fi)
{
    uint64_t inode_num = xrayfs_pathlookup(path);
    uint8_t** list;
    size_t len = 0;
    ssize_t readb = 0, toread = 0, ret = 0;
    uint64_t position = 0, sector = 0, i = 0;
    struct stat st;
    int64_t start = offset / 4096, end;

    if (xrayfs_getattr(path, &st))
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

        lseek(fd_disk, sector * 512 + offset % block_size, SEEK_SET);
        readb = 0;

        if (position + block_size - offset % block_size < size)
            toread = block_size - offset % block_size;
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

    //redis_free_list(list, len);

    return position;
}

/**
 *  main runs FUSE program and mounts passed in commandline path
 *  Need to:
 *      (1) disable inode cache, data cache
 */
int main(int argc, char* argv[])
{
    struct ext4_superblock superblock;
    const char* path = argv[argc - 1];
    handle = redis_init("4", false);
    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    fd_disk = open(path, O_RDONLY);
    argc -= 1;

    if (qemu_get_superblock(handle, &superblock, (uint64_t) 0))
        return EXIT_FAILURE;

    block_size = ext4_block_size(superblock);

    if (qemu_get_pt_offset(handle, &partition_offset, (uint64_t) 0))
        return EXIT_FAILURE;

    return fuse_main(argc, argv, &xrayfs_oper, NULL);
}
