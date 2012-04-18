#ifndef __ANALYSIS_ENGINE_DEEP_INSPECTION_H
#define __ANALYSIS_ENGINE_DEEP_INSPECTION_H

#include "bst.h"
#include "linkedlist.h"
#include "ext2.h"

#include <stdbool.h>

/* write event */
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

struct qemu_bdrv_write_header
{
    int64_t sector_num;
    int nb_sectors;
}__attribute__((packed));

struct qemu_bdrv_write
{
    struct qemu_bdrv_write_header header;
    const uint8_t* data;
};


/* custom indexes */
struct mbr
{
    bool gpt;
    uint64_t sector;
    uint64_t active_partitions;
    struct linkedlist* pt;
};

struct ext2_fs
{
    uint64_t fs_type;
    char* mount_point;
    uint64_t num_block_groups;
    uint64_t num_files;
    struct ext2_superblock superblock;
    struct linkedlist* ext2_bgds;
    struct linkedlist* ext2_files;
};

struct partition
{
    uint64_t pte_num;
    uint64_t partition_type;
    uint64_t first_sector_lba;
    uint64_t final_sector_lba;
    uint64_t sector;
    struct ext2_fs fs;
};

struct ext2_file
{
    char* path;
    bool is_dir;
    struct ext2_inode inode;
    struct bst_node* sectors;
};

struct ext2_bgd
{
    struct ext2_block_group_descriptor bgd;
    uint64_t sector;
    uint64_t block_bitmap_sector_start;
    uint64_t block_bitmap_sector_end;
    uint64_t inode_bitmap_sector_start;
    uint64_t inode_bitmap_sector_end;
    uint64_t inode_table_sector_start;
    uint64_t inode_table_sector_end;
};

/* functions */
void qemu_parse_header(uint8_t* data, struct qemu_bdrv_write* write);
int qemu_load_index(FILE* index, struct mbr* mbr);
int qemu_print_write(struct qemu_bdrv_write* write);
int qemu_infer_sector_type(struct qemu_bdrv_write* write, struct mbr* mbr);
int qemu_print_sector_type(enum SECTOR_TYPE type);

#endif
