#ifndef __ANALYSIS_ENGINE_DEEP_INSPECTION_H
#define __ANALYSIS_ENGINE_DEEP_INSPECTION_H

#include "ext2.h"
#include "ext4.h"
#include "ntfs.h"
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
int qemu_load_index(FILE* index, struct kv_store* store);
int qemu_load_md_filter(FILE* index, struct bitarray** bits);
int qemu_print_write(struct qemu_bdrv_write* write);
enum SECTOR_TYPE qemu_infer_sector_type(struct ext4_superblock* super,
                                        struct qemu_bdrv_write* write, 
                                        struct kv_store* store);
enum SECTOR_TYPE qemu_infer_ntfs_sector_type(struct ntfs_boot_file* bootf,
                                             struct qemu_bdrv_write* write, 
                                             struct kv_store* store);
int qemu_deep_inspect_ntfs(struct ntfs_boot_file* bootf,
                           struct qemu_bdrv_write* write, struct kv_store* store,
                           uint64_t write_counter, char* vmname,
                           uint64_t partition_offset);
int qemu_get_superblock(struct kv_store* store,
                        struct ext4_superblock* superblock,
                        uint64_t fs_id);
int qemu_get_bootf(struct kv_store* store,
                   struct ntfs_boot_file* bootf,
                   uint64_t fs_id);
int qemu_get_pt_offset(struct kv_store* store,
                       uint64_t* partition_offset,
                       uint64_t pt_id);
int qemu_print_sector_type(enum SECTOR_TYPE type);
int qemu_deep_inspect(struct ext4_superblock* superblock,
                      struct qemu_bdrv_write* write, struct kv_store* store,
                      uint64_t write_counter, char* vmname,
                      uint64_t partition_offset);
#endif
