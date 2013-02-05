#ifndef __XRAY_FS_H_
#define __XRAY_FS_H_

#define FUSE_USE_VERSION 28

#include <fuse.h>

static int xrayfs_getattr(const char* path, struct stat* stbuf);
static int xrayfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info* fi);
static int xrayfs_open(const char* path, struct fuse_file_info* fi);
static int xrayfs_read(const char* path, char* buf, size_t size, off_t offset,
                       struct fuse_file_info* fi);
static int xrayfs_readlink(const char* path, char* buf, size_t bufsize);

static struct fuse_operations xrayfs_oper = {
                                                .getattr    = xrayfs_getattr,
                                                .open       = xrayfs_open,
                                                .read       = xrayfs_read,
                                                .readdir    = xrayfs_readdir,
                                                .readlink   = xrayfs_readlink
                                             };

#endif
