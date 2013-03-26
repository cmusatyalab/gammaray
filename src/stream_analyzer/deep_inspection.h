#ifndef __ANALYSIS_ENGINE_DEEP_INSPECTION_H
#define __ANALYSIS_ENGINE_DEEP_INSPECTION_H

#include "ext2.h"
#include "ext4.h"
#include "ntfs.h"
#include "mbr.h"
#include "redis_queue.h"
#include "qemu_common.h"

#include <stdbool.h>

#define FIELD_COMPARE(field, fname, type, btype) {\
    if (old->field != new->field) \
        __emit_field_update(store, fname, type, channel, btype, \
                            &(old->field), &(new->field), sizeof(old->field), \
                            sizeof(new->field), write_counter, true, false); }

#define DIRECT_FIELD_COMPARE(field, fname, type, btype) {\
    if (field != new_##field) \
        __emit_field_update(store, fname, type, channel, btype, \
                            &(field), &(new_##field), sizeof(field), \
                            sizeof(new_##field), write_counter, true, false); }

#define GET_FIELD(cmd, id, field, len) {\
   len = sizeof(field); \
   if (redis_hash_field_get(store, cmd, id, \
                            #field, (uint8_t*) &field, &len)) \
    fprintf_light_red(stderr, "Error getting field: %s\n", #field); }

#define SET_FIELD(cmd, id, field, len) {\
   len = sizeof(new_##field); \
   if ((new_##field != field) && \
       redis_hash_field_set(store, cmd, id, \
                            #field, (uint8_t*) &new_##field, len)) \
    fprintf_light_red(stderr, "Error setting field: %s\n", #field); }

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

struct super_info
{
    uint64_t superblock_sector;
    uint64_t superblock_offset;
    uint64_t block_size;
    uint64_t blocks_per_group;
    uint64_t inodes_per_group;
    uint64_t inode_size;
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
int qemu_get_superinfo(struct kv_store* store,
                       struct super_info* superblock,
                       uint64_t fs_id);
int qemu_get_bootf(struct kv_store* store,
                   struct ntfs_boot_file* bootf,
                   uint64_t fs_id);
int qemu_get_pt_offset(struct kv_store* store,
                       uint64_t* partition_offset,
                       uint64_t pt_id);
int qemu_print_sector_type(enum SECTOR_TYPE type);
int qemu_deep_inspect(struct super_info* superblock,
                      struct qemu_bdrv_write* write, struct kv_store* store,
                      uint64_t write_counter, char* vmname,
                      uint64_t partition_offset,
                      FILE* index);
#endif
