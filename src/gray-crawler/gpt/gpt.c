/*****************************************************************************
 * gpt.c                                                                     *
 *                                                                           *
 * This file contains function implementations that can read and interpret a *
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bson.h"
#include "color.h"
#include "mbr.h"
#include "gpt.h"
#include "util.h"

/* static int print_partition_type(uint8_t type) */
/* { */
/*     fprintf_light_magenta(stdout, "TODO\n"); */
/*     /1* fprintf_light_magenta(stdout, "Partition Type: %s\n", gpt_PT_LUT[type]); *1/ */
/*     return -1; */
/* } */

/* static uint8_t get_sector(uint8_t byte) */
/* { */
/*     fprintf_light_magenta(stdout, "TODO\n"); */
/*     return 0x3f & byte; /1* bits 5-0 in second byte of chs *1/ */
/* } */

/* static uint16_t get_cylinder(uint8_t bytes[2]) */
/* { */
/*     fprintf_light_magenta(stdout, "TODO\n"); */
/*     return -1; */
/* } */

int64_t gpt_partition_offset(struct disk_gpt gpt, int pte)
{
    fprintf_light_magenta(stdout, "gpt_partition_offset\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return 0;
}

/* Prints GPT according to Wikipedia:
 * http://en.wikipedia.org/wiki/GUID_Partition_Table */
void gpt_print(struct pt pt)
{
    fprintf_light_magenta(stdout, "gpt_print\n"); // TODO: Remove.

    struct disk_mbr* mbr = (struct disk_mbr*) pt.pt_info;

    fprintf_light_cyan(stdout, "\n\nAnalyzing Protective MBR Header\n");

    fprintf_yellow(stdout, "Disk Signature [optional]: 0x%.8"PRIx32"\n",
                            mbr->disk_signature);

    fprintf_yellow(stdout, "Position 444 [0x0000]: 0x%.4"PRIx16"\n",
                           mbr->reserved);

    if (mbr->signature[0] == 0x55 && mbr->signature[1] == 0xaa)
    {
        fprintf_light_green(stdout, "Verifying MBR Signature [0x55 0xaa]: "
                                    "0x%.2"PRIx8" 0x%.2"
                                    PRIx8"\n\n",
                                    mbr->signature[0],
                                    mbr->signature[1]);
    }
    else
    {
        fprintf_light_red(stdout, "Verifying MBR Signature [0x55 0xaa]: 0x%.2"
                                  PRIx8" 0x%.2"PRIx8"\n\n",
                                  mbr->signature[0],
                                  mbr->signature[1]);
    }

    fprintf_light_cyan(stdout, "\n\nAnalyzing Primary GPT Header\n");
    struct disk_gpt* gpt = (struct disk_gpt*)
        (pt.pt_info + sizeof(struct disk_mbr));
    fprintf_yellow(stdout, "Signature: 0x%.16"PRIx64"\n", gpt->signature);
    fprintf_yellow(stdout, "Revision: 0x%.8"PRIx32"\n", gpt->revision);
    fprintf_yellow(stdout, "Header Size: 0x%.8"PRIx32"\n", gpt->header_size);
    fprintf_yellow(stdout, "Header CRC32: 0x%.8"PRIx32"\n", gpt->crc32_header);
    fprintf_yellow(stdout, "Current LBA: 0x%.16"PRIx64"\n", gpt->current_lba);
    fprintf_yellow(stdout, "Backup LBA: 0x%.16"PRIx64"\n", gpt->backup_lba);
    fprintf_yellow(stdout, "First Usable LBA: 0x%.16"PRIx64"\n",
            gpt->first_usable_lba);
    fprintf_yellow(stdout, "Last Usable LBA: 0x%.16"PRIx64"\n",
            gpt->last_usable_lba);
    fprintf_yellow(stdout, "Disk GUID: "
        "0x%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8
        "%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8
        "%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8
        "%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"\n",
        gpt->disk_guid[0],gpt->disk_guid[1],gpt->disk_guid[2],
        gpt->disk_guid[3],gpt->disk_guid[4],gpt->disk_guid[5],
        gpt->disk_guid[6],gpt->disk_guid[7],gpt->disk_guid[8],
        gpt->disk_guid[9],gpt->disk_guid[10],gpt->disk_guid[11],
        gpt->disk_guid[12],gpt->disk_guid[13],gpt->disk_guid[14],
        gpt->disk_guid[15]);
    fprintf_yellow(stdout, "Starting LBA partition entries: 0x%.16"PRIx64"\n",
            gpt->starting_lba_partition_entries);
    fprintf_yellow(stdout, "Number of partition entries: 0x%.8"PRIx32"\n",
            gpt->num_partition_entries);
    fprintf_yellow(stdout, "Size of a single partition entry: 0x%.8"PRIx32"\n",
            gpt->partition_entry_size);
    fprintf_yellow(stdout, "CRC32 of partition array: 0x%.8"PRIx32"\n",
            gpt->crc32_partition_array);
}

int gpt_probe(FILE* disk, struct pt* pt)
{
    fprintf_light_magenta(stdout, "gpt_probe\n"); // TODO: Remove.
    pt->pt_info = malloc(sizeof(struct disk_mbr) + sizeof(struct disk_gpt));
    struct disk_mbr* mbr = (struct disk_mbr*) pt->pt_info;

    if (fread(mbr, 1, sizeof(struct disk_mbr), disk) < sizeof(struct disk_mbr))
    {
        fprintf_light_red(stderr, "Error reading MBR from raw disk file.\n");
        return -1;
    }

    printf("mbr->sig: %x\n", mbr->signature[0]);
    if (mbr->signature[0] != 0x55 || mbr->signature[1] != 0xaa)
    {
        fprintf_light_red(stderr, "Bad MBR signature: "
                                  "%.2"PRIx8" %.2"PRIx8".\n",
                                  mbr->signature[0],
                                  mbr->signature[1]);
        return -1;
    }

    struct disk_gpt* gpt = (struct disk_gpt*)
        (pt->pt_info + sizeof(struct disk_mbr));
    if (fread(gpt, 1, sizeof(struct disk_gpt), disk) < sizeof(struct disk_gpt))
    {
        fprintf_light_red(stderr, "Error reading GPT from raw disk file.\n");
        return -1;
    }

    if (memcmp(&gpt->signature, "EFI PART", 8)) {
        fprintf_light_red(stderr, "Bad GPT signature: %.16"PRIx64".\n",
          gpt->signature);
        return -1;
    }

    return 0;
}

int gpt_cleanup_pt(struct pt pt)
{
    fprintf_light_magenta(stdout, "gpt_cleanup_pt\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return 0;
}

int gpt_cleanup_pte(struct pte pte)
{
    fprintf_light_magenta(stdout, "gpt_cleanup_pte\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return 0;
}

int gpt_serialize_pt(struct pt pt, struct bitarray* bits,
                     FILE* serializef)
{
    fprintf_light_magenta(stdout, "gpt_serialize_pt\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return -1;
}

bool gpt_get_next_partition(struct pt pt, struct pte* pte)
{
    fprintf_light_magenta(stdout, "gpt_get_next_partition\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return false;
}

int gpt_serialize_pte(struct pte pt_pte,
                      FILE* serializef)
{
    fprintf_light_magenta(stdout, "gpt_serialize_pte\n");
    fprintf_light_magenta(stdout, "TODO\n");
    return -1;
}
