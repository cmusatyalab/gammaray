#ifndef __XRAY_DISK_ANALYZER_MBR_H
#define __XRAY_DISK_ANALYZER_MBR_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "color.h"

struct partition_table_entry
{
    uint8_t status;
    uint8_t start_chs[3];
    uint8_t partition_type;
    uint8_t end_chs[3];
    uint32_t first_sector_lba;
    uint32_t sector_count;
}__attribute__((packed));

struct mbr
{
    uint8_t code[440];
    uint32_t disk_signature;
    uint16_t reserved;
    struct partition_table_entry pt[4];
    uint8_t signature[2];
}__attribute__((packed));

int print_mbr(struct mbr mbr);
int print_partition(struct partition_table_entry);
int parse_mbr(FILE* disk, struct mbr* mbr);
int64_t next_partition_offset(struct mbr mbr);

#endif
