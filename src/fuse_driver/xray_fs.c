#include <errno.h>

#include "xray_fs.h"

/**
 *  This function must implement the following:
 *      (1) Lookup path from '/' recursively in Redis (dentries)
 *      (2) If path doesn't exist return -ENOENT
 *      (3) Return inode number >= 0
 */
static int xrayfs_pathlookup(const char* path)
{
    return -ENOSYS;
}


/**
 *  This function must implement the following:
 *      (1) Lookup path from '/' recursively in Redis (dentries)
 *      (2) If path doesn't exist, return -ENOENT
 *      (3) Else pull inode, setup stbuf
 *      (4) Return 0
 */
static int xrayfs_getattr(const char* path, struct stat* stbuf)
{
    int inode_num = xrayfs_pathlookup(path);
    if (inode_num < 0)
        return -ENOENT;

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
    return -ENOSYS;
}

/**
 *  This function must implement the following:
 *      (1) Lookup path from '/' recursively in Redis (dentries)
 *      (2) If path doesn't exist, return -ENOENT
 *      (3) Else if not read-only return -ENORFS
 *      (4) Return 0
 */
static int xrayfs_open(const char* path, struct fuse_file_info* fi)
{
    return -ENOSYS;
}

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
    return fuse_main(argc, argv, &xrayfs_oper, NULL);
}
