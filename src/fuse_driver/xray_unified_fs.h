#ifndef __XRAY_FS_H_
#define __XRAY_FS_H_

#define FUSE_USE_VERSION 28

#include <fuse.h>

static int xrayfs_unified_getattr(const char* path, struct stat* stbuf);
static int xrayfs_unified_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info* fi);
static int xrayfs_unified_open(const char* path, struct fuse_file_info* fi);
static int xrayfs_unified_read(const char* path, char* buf, size_t size, off_t offset,
                       struct fuse_file_info* fi);
static int xrayfs_unified_readlink(const char* path, char* buf, size_t bufsize);

static struct fuse_operations xrayfs_unified_oper = {
                                                .getattr    = xrayfs_unified_getattr,
                                                .open       = xrayfs_unified_open,
                                                .read       = xrayfs_unified_read,
                                                .readdir    = xrayfs_unified_readdir,
                                                .readlink   = xrayfs_unified_readlink
                                             };

#endif
