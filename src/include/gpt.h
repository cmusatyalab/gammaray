/*****************************************************************************
 * gpt.h                                                                     *
 *                                                                           *
 * This file contains function prototypes that can read and interpret a      *
 * Global Partition Table (gpt).                                             *
 *                                                                           *
 *                                                                           *
 *                                                                           *
 *   Authors: Brandon Amos <bamos@cs.cmu.edu>                                *
 *            Wolfgang Richter <wolf@cs.cmu.edu>                             *
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
#ifndef __GAMMARAY_DISK_CRAWLER_gpt_H
#define __GAMMARAY_DISK_CRAWLER_gpt_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"
#include "gray-crawler.h"

struct disk_gpt
{
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32_header;
    uint32_t reserved_1;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t starting_lba_partition_entries;
    uint32_t num_partition_entries;
    uint32_t partition_entry_size;
    uint32_t crc32_partition_array;
    void* reserved_2;
}__attribute__((packed));

int gpt_probe(FILE* disk, struct pt* pt);
void gpt_print(struct pt pt);
int gpt_serialize_pt(struct pt pt, struct bitarray* bits,
                     FILE* serializef);
int gpt_serialize_pte(struct pte pte, FILE* serializef);
bool gpt_get_next_partition(struct pt pt, struct pte* pte);
int gpt_cleanup_pt(struct pt pt);
int gpt_cleanup_pte(struct pte pte);
#endif

