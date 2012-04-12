#ifndef __XRAY_DISK_ANALYZER_MBR_H
#define __XRAY_DISK_ANALYZER_MBR_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

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

struct mbr
{
    uint8_t code[440];
    uint32_t disk_signature;
    uint16_t reserved;
    struct partition_table_entry pt[4];
    uint8_t signature[2];
}__attribute__((packed));

int print_mbr(struct mbr mbr);
int print_partition(struct partition_table_entry pte);
int print_partition_sectors(struct partition_table_entry pte);
int parse_mbr(FILE* disk, struct mbr* mbr);
int64_t mbr_partition_offset(struct mbr mbr, int pte);
int mbr_get_partition_table_entry(struct mbr mbr, int pte_num,
                                  struct partition_table_entry* pte);
int mbr_print_numbers(struct mbr mbr);
int mbr_serialize_mbr(struct mbr mbr, FILE* serializef);
int mbr_serialize_partition(uint32_t pte_num, struct partition_table_entry pte,
                            char* mount_point,
                            FILE* serializef);

#endif
