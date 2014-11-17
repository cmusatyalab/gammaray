/*****************************************************************************
 * ntfs.h                                                                    *
 *                                                                           *
 * This file contains function prototypes that can read and interpret an NTFS*
 * file system.                                                              *
 *                                                                           *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013-2014 Carnegie Mellon University                          *
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
#ifndef __GAMMARAY_DISK_CRAWLER_NTFS_H
#define __GAMMARAY_DISK_CRAWLER_NTFS_H

#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"
#include "bson.h"
#include "gray-crawler.h"

enum NTFS_ATTRIBUTE_TYPE
{
    NTFS_STANDARD_INFORMATION    =   0x10,
    NTFS_ATTRIBUTE_LIST          =   0x20,
    NTFS_FILE_NAME               =   0x30,
    NTFS_VOLUME_VERSION          =   0x40,
    NTFS_OBJECT_ID               =   0x40,
    NTFS_SECURITY_DESCRIPTOR     =   0x50,
    NTFS_VOLUME_NAME             =   0x60,
    NTFS_VOLUME_INFORMATION      =   0x70,
    NTFS_DATA                    =   0x80,
    NTFS_INDEX_ROOT              =   0x90,
    NTFS_INDEX_ALLOCATION        =   0xA0,
    NTFS_BITMAP                  =   0xB0,
    NTFS_SYMBOLIC_LINK           =   0xC0,
    NTFS_REPARSE_POINT           =   0xC0,
    NTFS_EA_INFORMATION          =   0xD0,
    NTFS_EA                      =   0xE0,
    NTFS_PROPERTY_SET            =   0xF0,
    NTFS_LOGGED_UTILITY_STREAM   =   0x100
};

/* partition start, for probing and bootstrapping */
struct ntfs_boot_file
{
    uint8_t jump[3];
    int8_t sys_id[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;    
    uint8_t unused[7];
    uint8_t media;
    uint16_t unused2;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint8_t unused3[8];
    uint32_t signature;
    uint64_t sectors_in_volume;
    uint64_t lcn_mft;
    uint64_t lcn_mftmirr;
    int32_t clusters_per_mft_record;
    int32_t clusters_per_index_record;
    uint32_t volume_serial;
} __attribute__((packed));

/* MFT Parsing; full attribute header */
struct ntfs_standard_attribute_header
{
    uint32_t attribute_type;
    uint32_t length;
    uint8_t non_resident_flag;
    uint8_t name_length;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t attribute_id;
    uint32_t length_of_attribute;
    uint16_t offset_of_attribute;
    uint8_t indexed_flag;
    uint8_t padding;
} __attribute__((packed));

struct ntfs_non_resident_header
{
    uint64_t last_vcn;
    uint16_t data_run_offset;
    uint16_t compression_size;
    uint32_t padding;
    uint64_t allocated_size;
    uint64_t real_size;
    uint64_t initialized_size;
} __attribute__((packed));

int ntfs_probe(int disk, struct fs* fs);
int ntfs_serialize(int disk, struct fs* fs, int serializef);
int ntfs_cleanup(struct fs* fs);
uint64_t ntfs_file_record_size(struct ntfs_boot_file* bootf);
uint64_t ntfs_cluster_size(struct ntfs_boot_file* bootf);
int ntfs_get_attribute(uint8_t* record, void* attr, uint64_t* offset,
                      enum NTFS_ATTRIBUTE_TYPE type, char* name);
int ntfs_read_non_resident_attribute_header(uint8_t* data, uint64_t* offset,
                                            struct ntfs_non_resident_header*
                                            nrh);
int ntfs_print_non_resident_header(struct ntfs_non_resident_header* header);
int ntfs_parse_data_run(uint8_t* data, uint64_t* offset,
                        uint64_t* length, int64_t* lcn);
uint64_t ntfs_lcn_to_offset(struct ntfs_boot_file* bootf,
                            int64_t partition_offset, uint64_t lcn);
#endif
