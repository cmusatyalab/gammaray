#ifndef __STREAM_ANALYZER_QEMU_TRACER_H
#define __STREAM_ANALYZER_QEMU_TRACER_H

#include <inttypes.h>

#define BDRV_CO_IO_EM "bdrv_co_io_em"
#define QEMU_HEADER_SIZE sizeof(struct qemu_bdrv_write_header)

enum SECTOR_TYPE
{
    SECTOR_UNKNOWN = -1,
    SECTOR_MBR = 0,
    SECTOR_EXT2_PARTITION = 1,
    SECTOR_EXT2_SUPERBLOCK = 2,
    SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR = 3,
    SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP = 4,
    SECTOR_EXT2_BLOCK_GROUP_INODEMAP = 5,
    SECTOR_EXT2_INODE = 6,
    SECTOR_EXT2_DATA = 7
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

struct qemu_bdrv_write_header
{
    int64_t sector_num;
    int nb_sectors;
}__attribute__((packed));

struct qemu_bdrv_write
{
    struct qemu_bdrv_write_header header;
    uint8_t* data;
};

int64_t qemu_sizeof_header();
int64_t qemu_parse_header(uint8_t* event_stream,
                          struct qemu_bdrv_write* write);
int qemu_print_write(struct qemu_bdrv_write write);
int qemu_infer_sector_type(struct qemu_bdrv_write write);
int qemu_print_sector_type(int type);
#endif
