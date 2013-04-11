/*****************************************************************************
 * qemu_common.h                                                             *
 *                                                                           *
 * This file contains function prototypes for parsing binary data from QEMU. *
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
#ifndef __ANALYSIS_ENGINE_QEMU_COMMON_H
#define __ANALYSIS_ENGINE_QEMU_COMMON_H

#include <inttypes.h>

#define QEMU_HEADER_SIZE sizeof(struct qemu_bdrv_write_header)
#define SECTOR_SIZE 512

enum SECTOR_TYPE
{
    SECTOR_UNKNOWN = -1,
    SECTOR_MBR = 0,
    SECTOR_EXT2_PARTITION = 1,
    SECTOR_EXT2_SUPERBLOCK = 2,
    SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR = 3,
    SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP = 4,
    SECTOR_EXT2_BLOCK_GROUP_INODEMAP = 5,
    SECTOR_EXT2_INODE = 6,
    SECTOR_EXT2_DATA = 7,
    SECTOR_EXT4_EXTENT = 8
};

struct qemu_bdrv_write_header
{
    int64_t sector_num;
    int nb_sectors;
} __attribute__((packed));

struct qemu_bdrv_write
{
    struct qemu_bdrv_write_header header;
    uint8_t* data;
};

void qemu_parse_header(uint8_t* event_stream, struct qemu_bdrv_write* write);

#endif
