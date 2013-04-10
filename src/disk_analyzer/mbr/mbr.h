/*****************************************************************************
 * mbr.h                                                                     *
 *                                                                           *
 * This file contains function prototypes that can read and interpret a      *
 * Master Boot Record (MBR).                                                 *
 *                                                                           *
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
#ifndef __GAMMARAY_DISK_ANALYZER_MBR_H
#define __GAMMARAY_DISK_ANALYZER_MBR_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"
#include "color.h"

#define SECTOR_SIZE 512

struct partition_table_entry
{
    uint8_t status;
    uint8_t start_chs[3];
    uint8_t partition_type;
    uint8_t end_chs[3];
    uint32_t first_sector_lba;
    uint32_t sector_count;
}__attribute__((packed));

struct disk_mbr
{
    uint8_t code[440];
    uint32_t disk_signature;
    uint16_t reserved;
    struct partition_table_entry pt[4];
    uint8_t signature[2];
}__attribute__((packed));

int mbr_print_mbr(struct disk_mbr mbr);
int mbr_parse_mbr(FILE* disk, struct disk_mbr* mbr);
int mbr_get_partition_table_entry(struct disk_mbr mbr, int pte_num,
                                  struct partition_table_entry* pte);
int mbr_serialize_mbr(struct disk_mbr mbr, struct bitarray* bits,
                      uint32_t active, FILE* serializef);
int mbr_serialize_partition(uint32_t pte_num, struct partition_table_entry pte,
                            FILE* serializef);
#endif
