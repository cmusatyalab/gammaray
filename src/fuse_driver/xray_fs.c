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
    uint64_t field;
    size_t len2 = sizeof(field);
    
    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "size",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_size = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "mode",
                             (uint8_t*) &field, &len2))
        return -ENOENT;
    
    stbuf->st_mode = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "link_count",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_nlink = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "uid",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_uid = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "gid",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_gid = field;

    stbuf->st_blksize = block_size;
    stbuf->st_blocks = (stbuf->st_size % 512) ? stbuf->st_size / 512 + 1 : 
                                                stbuf->st_size / 512;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "atime",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_atime = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "mtime",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_mtime = field;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "ctime",
                             (uint8_t*) &field, &len2))
        return -ENOENT;

    stbuf->st_ctime = field;

    return 0;
}

static int xrayfs_readlink(const char* path, char* buf, size_t bufsize)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    size_t len = bufsize;

    memset(buf, 0, bufsize);

    if (inode_num < 0)
        return -ENOENT;

    if (redis_hash_field_get(handle, REDIS_FILE_SECTOR_GET, inode_num, "link_name",
                             (uint8_t*) buf, &len))
        return -ENOENT;

    return 0;

}

static int xrayfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                                  off_t offset, struct fuse_file_info* fi)
{
    int64_t inode_num = xrayfs_pathlookup(path);
    uint8_t **slist = NULL, **dlist = NULL;
    size_t slen = 0, dlen = 0;
    uint64_t sector = 0, i = 0, j = 0;

    if (inode_num < 0)
        return -ENOENT;

    if (redis_list_get(handle, REDIS_FILE_SECTORS_LGET,
                       inode_num, &slist, &slen))
        return -ENOENT;

    /* for all folder sectors (length of folder on disk/positions) */
    for (i = 0; i < slen; i++)
    {
        fprintf_light_yellow(stderr, "strtok()ing.\n");
        strtok((char*) (slist)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &sector);

        if (redis_list_get(handle, REDIS_DIR_FILES_LGET, sector,
                           &dlist, &dlen))
            return -ENOENT;

        /* for every dentry in that sector */
        for (j = 0; j < dlen; j++)
        {
            filler(buf, (const char*) &(dlist[j][8]), NULL, 0);
        }

        redis_free_list(dlist, dlen);

    }

    redis_free_list(slist, slen);

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

        if (toread <= 0)
            break;

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

/**
 *  main runs FUSE program and mounts passed in commandline path
 *  Need to:
 *      (1) disable inode cache, data cache
 */
int main(int argc, char* argv[])
{
    const char* path = argv[argc - 1];
    size_t len = sizeof(uint64_t);
    handle = redis_init("4", false);
    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    fd_disk = open(path, O_RDONLY);
    argc -= 1;

    if (redis_hash_field_get(handle, REDIS_SUPERBLOCK_SECTOR_GET, 0, "block_size",
                             (uint8_t*) &block_size, &len))
        return -ENOENT;

    if (len != 8)
        return EXIT_FAILURE;

    if (qemu_get_pt_offset(handle, &partition_offset, (uint64_t) 0))
        return EXIT_FAILURE;

    return fuse_main(argc, argv, &xrayfs_oper, NULL);
}
