/*****************************************************************************
 * mbr.c                                                                     *
 *                                                                           *
 * This file contains function implementations that can read and interpret a *
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bson.h"
#include "color.h"
#include "mbr.h"
#include "util.h"

#define SECTOR_SIZE 512

char* MBR_PT_LUT[] = { "Empty","","","","","Extended","","HPFS/NTFS","","","","W95 FAT32","","","","", /* 0x00 - 0x0f */
                       "","","","","","","","","","","","","","","","", /* 0x10 - 0x1f */
                       "","","","","","","","","","","","","","","","", /* 0x20 - 0x2f */
                       "","","","","","","","","","","","","","","","", /* 0x30 - 0x3f */
                       "","","","","","","","","","","","","","","","", /* 0x40 - 0x4f */
                       "","","","","","","","","","","","","","","","", /* 0x50 - 0x5f */
                       "","","","","","","","","","","","","","","","", /* 0x60 - 0x6f */
                       "","","","","","","","","","","","","","","","", /* 0x70 - 0x7f */
                       "","","Linux Swap","Linux","","Linux Extended","","","","","","","","","Linux LVM","", /* 0x80 - 0x8f */
                       "","","","","","","","","","","","","","","","", /* 0x90 - 0x9f */
                       "","","","","","","","","","","","","","","","HFS / HFS+", /* 0xa0 - 0xaf */
                       "","","","","","","","","","","","","","","","", /* 0xb0 - 0xbf */
                       "","","","","","","","","","","","","","","","", /* 0xc0 - 0xcf */
                       "","","","","","","","","","","","","","","","", /* 0xd0 - 0xdf */
                       "","","","","","","","","","","","","","","GPT","EFI", /* 0xe0 - 0xef */
                       "","","","","","","","","","","","","","","",""  /* 0xf0 - 0xff */
                     };

int print_partition_type(uint8_t type)
{
    fprintf_light_magenta(stdout, "Partition Type: %s\n", MBR_PT_LUT[type]);
    return -1;
}

uint8_t get_sector(uint8_t byte)
{
    return 0x3f & byte; /* bits 5-0 in second byte of chs */
}

uint16_t get_cylinder(uint8_t bytes[2])
{
    uint8_t b1 = bytes[0];
    uint8_t b2 = bytes[1];
    /* grab bits 9-0 */
    uint16_t cylinder = (b1 & 0xc0) << 2;
    return cylinder | b2;
}

int64_t mbr_partition_offset(struct disk_mbr mbr, int pte)
{
    /* linux partition match */
    if (mbr.pt[pte].partition_type == 0x83)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    /* Extended partition match */
    if (mbr.pt[pte].partition_type == 0x05)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    /* NTFS partition match */
    if (mbr.pt[pte].partition_type == 0x07)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    /* FAT32 partition match */
    if (mbr.pt[pte].partition_type == 0x0b)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    /* LVM partition match */
    if (mbr.pt[pte].partition_type == 0x8e)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    return 0;
}

/* prints partition entry according to Wikipedia:
 * http://en.wikipedia.org/wiki/Master_boot_record */
int mbr_print_partition(struct partition_table_entry pte)
{
    char size_buf[512];
    memset(size_buf, 0x00, 512);

    fprintf_blue(stdout, "Status [0x80 bootable, 0x00 non-bootable]: 0x%.2"
                         PRIx8"\n",
                         pte.status);
    fprintf_blue(stdout, "Partition Type: 0x%.2"
                    PRIx8"\n",
                    pte.partition_type);
    
    print_partition_type(pte.partition_type);

    /* check it partition entry is being used */
    if (pte.partition_type == 0x00) return -1;
    
    fprintf_blue(stdout, "Start Head: 0x%.2"
                    PRIx8"\n",
                    pte.start_chs[0]);
    fprintf_blue(stdout, "Start Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(pte.start_chs[1]));
    fprintf_blue(stdout, "Start Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(pte.start_chs[1])));
    fprintf_blue(stdout, "End Head: 0x%.2"
                    PRIx8"\n",
                    pte.end_chs[0]);
    fprintf_blue(stdout, "End Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(pte.end_chs[1]));
    fprintf_blue(stdout, "End Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(pte.end_chs[1])));
    fprintf_green(stdout, "First Sector LBA: 0x%.8"
                    PRIx32"\n",
                    pte.first_sector_lba);
    pretty_print_bytes((uint64_t) SECTOR_SIZE*pte.sector_count, size_buf, 512);
    fprintf_green(stdout, "Number of Sectors: 0x%.8"
                    PRIx32" (%s)\n",
                    pte.sector_count,
                    size_buf);
    return 0;
}

void mbr_print(struct pt pt)
{
    struct disk_mbr* mbr = (struct disk_mbr*) pt.pt_info;
    fprintf_light_cyan(stdout, "\n\nAnalyzing Boot Sector\n");

    /* Taking apart according to Wikipedia:            
     * http://en.wikipedia.org/wiki/Master_boot_record */
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

    /* read all 4 partition table entries */
    fprintf_light_yellow(stdout, "\nChecking partition table entry 0.\n");
    mbr_print_partition(mbr->pt[0]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 1.\n");
    mbr_print_partition(mbr->pt[1]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 2.\n");
    mbr_print_partition(mbr->pt[2]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 3.\n");
    mbr_print_partition(mbr->pt[3]);
}

int mbr_probe(FILE* disk, struct pt* pt)
{
    struct disk_mbr* mbr;
    pt->pt_info = malloc(sizeof(struct disk_mbr));
    mbr = (struct disk_mbr*) pt->pt_info;

    if (fread(mbr, 1, sizeof(struct disk_mbr), disk) < sizeof(struct disk_mbr))
    {
        fprintf_light_red(stderr, "Error reading MBR from raw disk file.\n");
        return -1;
    }

    if (mbr->signature[0] != 0x55 || mbr->signature[1] != 0xaa)
    {
        fprintf_light_red(stderr, "Bad MBR signature: "
                                  "%.2"PRIx8" %.2"PRIx8".\n",
                                  mbr->signature[0],
                                  mbr->signature[1]);
        return -1;
    }

    return 0;
}

int mbr_cleanup_pt(struct pt pt)
{
    if (pt.pt_info)
    {
        free(pt.pt_info);
    }

    return 0;
}

int mbr_cleanup_pte(struct pte pte)
{
    if (pte.pte_info)
    {
        free(pte.pte_info);
    }

    return 0;
}

int mbr_serialize_pt(struct pt pt, struct bitarray* bits,
                     FILE* serializef)
{
    struct bson_info* serialized;
    struct bson_kv value;
    struct disk_mbr* mbr = (struct disk_mbr*) pt.pt_info;
    bool has_gpt = false;
    int ret, sector = 0;

    if (mbr->pt[0].partition_type == 0xee)
        has_gpt = true;

    serialized = bson_init();

    value.type = BSON_STRING;
    value.size = strlen("mbr");
    value.key = "type";
    value.data = "mbr";

    bson_serialize(serialized, &value);

    value.type = BSON_BOOLEAN;
    value.key = "gpt";
    value.data = &(has_gpt);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "sector";
    value.data = &sector;

    bitarray_set_bit(bits, sector);

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    ret = bson_writef(serialized, serializef);
    bson_cleanup(serialized);
    
    return ret;
}

bool mbr_get_next_partition(struct pt pt, struct pte* pte)
{
    struct disk_mbr* mbr = (struct disk_mbr*) pt.pt_info;
    struct partition_table_entry* entry = (struct partition_table_entry*)
                                  malloc(sizeof(struct partition_table_entry));
    static int pte_num = 0;

    if (pte_num < 4)
    {
        memcpy(entry, &mbr->pt[pte_num], sizeof(struct partition_table_entry));
        pte->pt_num = pte_num;
        pte->pt_off = entry->first_sector_lba * SECTOR_SIZE;
        pte->pte_info = (void*) entry;
        pte_num++;
    }
    else
    {
        if (entry)
            free(entry);
        return false;
    }

    return true;
}

int mbr_serialize_pte(struct pte pt_pte,
                      FILE* serializef)
{
    struct bson_info* serialized;
    struct bson_kv value;
    struct partition_table_entry* pte = 
                             (struct partition_table_entry *) pt_pte.pte_info;
    int32_t partition_type;
    int32_t final_sector;
    int ret;

    partition_type = pte->partition_type;
    final_sector = pte->first_sector_lba + pte->sector_count;

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

    value.type = BSON_INT32;
    value.key = "partition_type";
    value.data = &(partition_type);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "first_sector_lba";
    value.data = &(pte->first_sector_lba);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "final_sector_lba";
    value.data = &(final_sector);

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    ret = bson_writef(serialized, serializef);
    bson_cleanup(serialized);
     
    return ret;
}
