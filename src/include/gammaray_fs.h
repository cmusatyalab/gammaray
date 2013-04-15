/*****************************************************************************
 * gammaray_fs.h                                                             *
 *                                                                           *
 * This file contains prototypes for functions implementing a FUSE read-only *
 * file-system view of metadata maintained by gammaray in its in-memory Redis*
 * store.                                                                    *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013 Carnegie Mellon University                               *
 *                                                                           *
 *   Licensed under the Apache License, Version 2.0 (the "License");         *
 *   you may not use this file except in compliance with the License.        *
 *   You may obtain a copy of the License at                                 *
 *                                                                           *
 *       http://www.apache.org/licenses/LICENSE-2.0                          *
 *                                                                           *
 *   Unless required by applicable law or agreed to in writing, software     *
 *   distributed under the License is distributed on an "AS IS" BASIS,       *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
 *   See the License for the specific language governing permissions and     *
 *   limitations under the License.                                          *
 *****************************************************************************/
#ifndef __GAMMARAY_FUSE_DRIVER_FS_H_
#define __GAMMARAY_FUSE_DRIVER_FS_H_

#define FUSE_USE_VERSION 28

#include <fuse.h>

static int gammarayfs_getattr(const char* path, struct stat* stbuf);
static int gammarayfs_readdir(const char* path, void* buf,
                              fuse_fill_dir_t filler, off_t offset,
                              struct fuse_file_info* fi);
static int gammarayfs_open(const char* path, struct fuse_file_info* fi);
static int gammarayfs_read(const char* path, char* buf, size_t size,
                           off_t offset, struct fuse_file_info* fi);
static int gammarayfs_readlink(const char* path, char* buf, size_t bufsize);

static struct fuse_operations gammarayfs_oper =
                                             {
                                              .getattr    = gammarayfs_getattr,
                                              .open       = gammarayfs_open,
                                              .read       = gammarayfs_read,
                                              .readdir    = gammarayfs_readdir,
                                              .readlink   = gammarayfs_readlink
                                             };

#endif
