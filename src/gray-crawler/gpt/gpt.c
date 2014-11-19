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
#include <unistd.h>

#include "bson.h"
#include "color.h"
#include "mbr.h"
#include "gpt.h"
#include "util.h"

#define SECTOR_SIZE 512

static void print_guid(uint8_t a[16]) {
  fprintf_yellow(stdout, "0x%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8
      "-%.2"PRIx8"%.2"PRIx8"-%.2"PRIx8"%.2"PRIx8
      "-%.2"PRIx8"%.2"PRIx8"-%.2"PRIx8"%.2"PRIx8
      "%.2"PRIx8"%.2"PRIx8"%.2"PRIx8"%.2"PRIx8,
      a[3],a[2],a[1],a[0],
      a[5],a[4],
      a[7],a[6],
      a[8],a[9],
      a[10],a[11],a[12],a[13],a[14],a[15]);
}

/* Prints GPT partiton according to Wikipedia:
 * http://en.wikipedia.org/wiki/GUID_Partition_Table */
static void gpt_partition_print(struct gpt_partition_table_entry gpt_pe)
{
    fprintf_yellow(stdout, "\nChecking partition table entry.\n");
    fprintf_green(stdout, "Partition type GUID: ");
    print_guid(gpt_pe.partition_type_guid);
    fprintf_green(stdout, "\n");
    fprintf_green(stdout, "Unique partition GUID: ");
    print_guid(gpt_pe.unique_partition_guid);
    fprintf_green(stdout, "\n");
    fprintf_green(stdout, "First LBA: 0x%.16"PRIx64"\n",
        gpt_pe.first_lba);
    fprintf_green(stdout, "Last LBA: 0x%.16"PRIx64"\n",
        gpt_pe.last_lba);
    fprintf_green(stdout, "Attribute Flags: 0x%.16"PRIx64"\n",
        gpt_pe.attribute_flags);
    fprintf_green(stdout, "Partition Name: '%s'\n",
        gpt_pe.partition_name);
}

/* Prints GPT according to Wikipedia:
 * http://en.wikipedia.org/wiki/GUID_Partition_Table */
void gpt_print(struct pt pt)
{
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
    fprintf_yellow(stdout, "Disk GUID: ");
    print_guid(gpt->disk_guid);
    fprintf_yellow(stdout, "\n");
    fprintf_yellow(stdout, "Starting LBA partition entries: 0x%.16"PRIx64"\n",
            gpt->starting_lba_partition_entries);
    fprintf_yellow(stdout, "Number of partition entries: 0x%.8"PRIx32"\n",
            gpt->num_partition_entries);
    fprintf_yellow(stdout, "Size of a single partition entry: 0x%.8"PRIx32"\n",
            gpt->partition_entry_size);
    fprintf_yellow(stdout, "CRC32 of partition array: 0x%.8"PRIx32"\n",
            gpt->crc32_partition_array);

    /* Read all partition table entries */
    struct gpt_partition_table_entry* cur_pt = gpt->pt;
    while (!(cur_pt->first_lba == 0x0 && cur_pt->last_lba == 0x0)) {
      gpt_partition_print(*cur_pt);
      cur_pt++;
    }
}

int gpt_probe(int disk, struct pt* pt)
{
    pt->pt_info = malloc(sizeof(struct disk_mbr) + sizeof(struct disk_gpt));
    struct disk_mbr* mbr = (struct disk_mbr*) pt->pt_info;

    if (read(disk, mbr, sizeof(struct disk_mbr)) < sizeof(struct disk_mbr))
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
    if (read(disk, gpt, sizeof(struct disk_gpt)) < sizeof(struct disk_gpt))
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
    if (pt.pt_info)
    {
        free(pt.pt_info);
    }
    return 0;
}

int gpt_cleanup_pte(struct pte pte)
{
    if (pte.pte_info)
    {
        free(pte.pte_info);
    }
    return 0;
}

bool gpt_get_next_partition(struct pt pt, struct pte* pte)
{
    static struct gpt_partition_table_entry* cur_pt = 0;
    static uint32_t pt_num = 1;

    if (!cur_pt) {
      struct disk_gpt* gpt = (struct disk_gpt*)
        (pt.pt_info + sizeof(struct disk_mbr));
      cur_pt = gpt->pt;
    }

    if (!(cur_pt->first_lba == 0x0 && cur_pt->last_lba == 0x0))
    {
        struct gpt_partition_table_entry* e = (struct gpt_partition_table_entry*)
          malloc(sizeof(struct gpt_partition_table_entry));
        memcpy(e, cur_pt, sizeof(struct gpt_partition_table_entry));
        pte->pt_num = pt_num;
        pte->pt_off = e->first_lba * SECTOR_SIZE;
        pte->pte_info = (void*) e;
        cur_pt++;
        pt_num++;
    }
    else
    {
        return false;
    }

    return true;
}

int gpt_serialize_pt(struct pt pt, struct bitarray* bits,
                     int serializef)
{
    struct bson_info* serialized;
    struct bson_kv value;
    /* struct disk_mbr* mbr = (struct disk_mbr*) pt.pt_info; */
    /* struct disk_gpt* gpt = (struct disk_gpt*) */
    /*   (pt.pt_info + sizeof(struct disk_mbr)); */
    int ret = 0;

    serialized = bson_init();

    value.type = BSON_STRING;
    value.size = strlen("gpt");
    value.key = "type";
    value.data = "gpt";

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    ret = bson_writef(serialized, serializef);
    bson_cleanup(serialized);

    return ret;
}


int gpt_serialize_pte(struct pte pt_pte,
                      int serializef)
{
    struct bson_info* serialized;
    struct bson_kv value;
    struct gpt_partition_table_entry* pte =
      (struct gpt_partition_table_entry *) pt_pte.pte_info;
    int ret;

    serialized = bson_init();

    value.type = BSON_STRING;
    value.size = strlen("partition");
    value.key = "type";
    value.data = "partition";

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "pte_num";
    value.data = &pt_pte.pt_num;

    bson_serialize(serialized, &value);

    value.type = BSON_BINARY;
    value.key = "partition_type_guid";
    value.data = pte->partition_type_guid;
    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "first_sector_lba";
    value.data = &(pte->first_lba);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "final_sector_lba";
    value.data = &(pte->last_lba);

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    ret = bson_writef(serialized, serializef);
    bson_cleanup(serialized);

    return ret;
}
