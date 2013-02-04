#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "deep_inspection.h"
#include "redis_queue.h"
#include "xray_fs.h"

static uint64_t partition_offset;
static uint64_t block_size;
static struct kv_store* handle;

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

    len2 = sizeof(stbuf->st_ino);

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num,
                             "inode_num", (uint8_t*) &(stbuf->st_ino),
                             &len2))
        return -ENOENT;

    stbuf->st_mode = inode.i_mode;
    stbuf->st_nlink = inode.i_links_count;
    stbuf->st_uid = inode.i_uid;
    stbuf->st_gid = inode.i_gid;
    stbuf->st_blksize = block_size;
    stbuf->st_size = ext4_file_size(inode);
    stbuf->st_blocks = stbuf->st_size / 512;
    stbuf->st_atime = inode.i_atime;
    stbuf->st_mtime = inode.i_mtime;
    stbuf->st_ctime = inode.i_ctime;

    return -ENOSYS;
}

/**
 *  This function must implement the following:
 *      (1) Lookup path from '/' recursively in Redis (dentries)
 *      (2) If path doesn't exist, return -ENOENT
 *      (3) Else pull dentry data, use filler for each dentry
 *      (4) Return 0
 */
static int xrayfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t data_buf[block_size];
    uint8_t** list;
    size_t len = 0;
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
        len = block_size;

        if (redis_hash_field_get(handle, REDIS_DIR_SECTOR_GET, sector, "data",
                                 data_buf, &len))
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

    return -ENOSYS;
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
    return -ENOSYS;
}

/**
 *  main runs FUSE program and mounts passed in commandline path
 *  Need to:
 *      (1) disable inode cache, data cache
 */
int main(int argc, char* argv[])
{
    struct ext4_superblock superblock;
    handle = redis_init("4", false);
    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    if (qemu_get_superblock(handle, &superblock, (uint64_t) 0))
        return EXIT_FAILURE;

    block_size = ext4_block_size(superblock);

    if (qemu_get_pt_offset(handle, &partition_offset, (uint64_t) 0))
        return EXIT_FAILURE;

    return fuse_main(argc, argv, &xrayfs_oper, NULL);
}
