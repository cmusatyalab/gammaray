#ifndef __ANALYSIS_ENGINE_DEEP_INSPECTION_H
#define __ANALYSIS_ENGINE_DEEP_INSPECTION_H

#include "ext2.h"
#include "ext4.h"
#include "mbr.h"
#include "redis_queue.h"
#include "qemu_common.h"

#include <stdbool.h>

/* custom indexes */
struct mbr
{
    bool gpt;
    uint64_t sector;
    uint64_t active_partitions;
    struct disk_mbr mbr;
} __attribute__((packed));

struct ext4_fs
{
    uint64_t fs_type;
    char* mount_point;
    uint64_t num_block_groups;
    uint64_t num_files;
    struct ext4_superblock superblock;
} __attribute__((packed));

struct partition
{
    uint64_t pte_num;
    uint64_t partition_type;
    uint64_t first_sector_lba;
    uint64_t final_sector_lba;
    uint64_t sector;
    struct ext4_fs fs;
} __attribute__packed;

struct ext4_file
{
    uint64_t inode_sector;
    uint64_t inode_offset;
    bool is_dir;
    struct ext4_inode inode;
} __attribute__((packed));

struct ext4_bgd
{
    struct ext4_block_group_descriptor bgd;
    uint64_t sector;
    uint64_t block_bitmap_sector_start;
    uint64_t block_bitmap_sector_end;
    uint64_t inode_bitmap_sector_start;
    uint64_t inode_bitmap_sector_end;
    uint64_t inode_table_sector_start;
    uint64_t inode_table_sector_end;
} __attribute__((packed));

/* functions */
int qemu_load_index(FILE* index, struct mbr* mbr, struct kv_store* store);
int qemu_print_write(struct qemu_bdrv_write* write);
enum SECTOR_TYPE qemu_infer_sector_type(struct qemu_bdrv_write* write, 
                                        struct kv_store* store,
                                        uint64_t block_size);
int qemu_print_sector_type(enum SECTOR_TYPE type);
uint64_t qemu_get_block_size(struct kv_store* store, uint64_t fs_id);
int qemu_deep_inspect(struct qemu_bdrv_write* write, struct kv_store* store,
                      char* vmname, uint64_t block_size);

#endif
