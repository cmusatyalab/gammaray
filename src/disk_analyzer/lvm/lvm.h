#ifndef XRAY_DISK_ANALYZER_LVM_H
#define XRAY_DISK_ANALYZER_LVM_H

#include <inttypes.h>
#include <stdint.h>

#define SECTOR_SIZE 512
#define LVM_META_MAGIC "\040\114\126\115\062\040\170\133\065\101\045\162\060\116\052\076"
#define LVM_LVMLABEL "LVM2 001"
#define LVM_LABEL_ID "LABELONE"

struct lvm_disk_locn
{
    uint64_t offset;
    uint64_t size;
} __attribute__((packed));

struct lvm_pv_header
{
    uint8_t pv_uuid[ID_LEN];
    uint64_t device_size_xl;
    struct disk_locn disk_areas_xl[0]; /* two lists follow oddly */
} __attribute__((packed));

struct lvm_raw_locn
{
    uint64_t offset;
    uint64_t size;
    uint32_t checksum;
    uint32_t flags;
} __attribute__((packed));

struct lvm_mda_header
{
    uint32_t checksum_xl;
    uint8_t magic[16];
    uint32_t version;
    uint64_t start;
    uint64_t size;
    struct raw_locn raw_locns[0];
} __attribute__((packed));

struct lvm_label_header 
{
    uint8_t id[8];
    uint64_t sector_xl;
    uint32_t crc_xl;
    uint32_t offset_xl;
    uint8_t type[8];
} __attribute__((packed));

int lvm_read_label_header(FILE* disk, int64_t partition_offset,
                          struct lvm_label_header* llh,);
int lvm_print_label_header(FILE* disk, int64_t partition_offset, 
                           struct lvm_label_header* llh);
#endif
