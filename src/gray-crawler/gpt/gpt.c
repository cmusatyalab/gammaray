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

#define SECTOR_SIZE 512

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

/* prints partition entry according to Wikipedia:
 * TODO: http://en.wikipedia.org/wiki/Master_boot_record */
/* int gpt_print_partition(struct partition_table_entry pte) */
/* { */
/*     fprintf_light_magenta(stdout, "TODO\n"); */
/*     return 0; */
/* } */

void gpt_print(struct pt pt)
{
    fprintf_light_magenta(stdout, "gpt_print\n");
    fprintf_light_magenta(stdout, "TODO\n");
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

    struct disk_gpt* gpt = (struct disk_gpt*) (pt->pt_info +
            sizeof(struct disk_mbr));
    if (fread(gpt, 1, sizeof(struct disk_gpt), disk) < sizeof(struct disk_gpt))
    {
        fprintf_light_red(stderr, "Error reading GPT from raw disk file.\n");
        return -1;
    }

    if (memcmp(gpt->signature, "EFI PART", 8)) {
        fprintf_light_red(stderr, "Bad GPT signature: "
          "%.2"PRIx8" %.2"PRIx8" %.2"PRIx8" %.2"PRIx8
          " %.2"PRIx8" %.2"PRIx8" %.2"PRIx8" %.2"PRIx8".\n",
          gpt->signature[0],gpt->signature[1],gpt->signature[2],
          gpt->signature[3],gpt->signature[4],gpt->signature[5],
          gpt->signature[6],gpt->signature[7]);
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
