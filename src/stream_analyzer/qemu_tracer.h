#ifndef __STREAM_ANALYZER_QEMU_TRACER_H
#define __STREAM_ANALYZER_QEMU_TRACER_H

#include <inttypes.h>

#define BDRV_CO_IO_EM "bdrv_co_io_em"

enum SECTOR_TYPE
{
    SECTOR_UNKNOWN = -1,
    SECTOR_MBR = 0,
    SECTOR_EXT2_PARTITION = 1,
    SECTOR_EXT2_SUPERBLOCK = 2,
    SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR = 3,
    SECTOR_EXT2_INODE = 4,
    SECTOR_EXT2_DATA = 5
};

struct partition
{
    int64_t start_sector;
    int64_t end_sector;
};

struct disk
{
    int64_t mbr_sector;
    struct partition partition_table[4];
};

struct qemu_bdrv_co_io_em
{
    uint32_t bs;
    int64_t sector;
    uint32_t sector_count;
    uint8_t write;
    uint32_t acb;
};

int64_t parse_write(uint8_t* event_stream, int64_t stream_size, 
                    struct qemu_bdrv_co_io_em* write);
int qemu_print_write(struct qemu_bdrv_co_io_em);
int qemu_infer_sector_type(struct qemu_bdrv_co_io_em write);
int qemu_print_sector_type(int type);
#endif
