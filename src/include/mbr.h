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
#ifndef __GAMMARAY_DISK_CRAWLER_MBR_H
#define __GAMMARAY_DISK_CRAWLER_MBR_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"
#include "gray-crawler.h"

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

int mbr_probe(int disk, struct pt* pt);
void mbr_print(struct pt pt);
int mbr_serialize_pt(struct pt pt, struct bitarray* bits,
                     int serializef);
int mbr_serialize_pte(struct pte pte, int serializef);
bool mbr_get_next_partition(struct pt pt, struct pte* pte);
int mbr_cleanup_pt(struct pt pt);
int mbr_cleanup_pte(struct pte pte);
#endif
