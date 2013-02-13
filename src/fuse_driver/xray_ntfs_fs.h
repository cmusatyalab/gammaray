#ifndef __XRAY_NTFS_FS_H_
#define __XRAY_NTFS_FS_H_

#define FUSE_USE_VERSION 28

#include <fuse.h>

static int xrayfs_ntfs_getattr(const char* path, struct stat* stbuf);
static int xrayfs_ntfs_readdir(const char* path, void* buf,
                               fuse_fill_dir_t filler, off_t offset,
                               struct fuse_file_info* fi);
static int xrayfs_ntfs_open(const char* path, struct fuse_file_info* fi);
static int xrayfs_ntfs_read(const char* path, char* buf, size_t size,
                            off_t offset, struct fuse_file_info* fi);

static struct fuse_operations xrayfs_ntfs_oper =
                                        {
                                            .getattr    = xrayfs_ntfs_getattr,
                                            .open       = xrayfs_ntfs_open,
                                            .read       = xrayfs_ntfs_read,
                                            .readdir    = xrayfs_ntfs_readdir
                                        };


#endif
