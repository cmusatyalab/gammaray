/*****************************************************************************
 * ext4.h                                                                    *
 *                                                                           *
 * This file contains function prototypes that can read and interpret an ext4*
 * file system.                                                              *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013 Carnegie Mellon University                               *
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
#ifndef __GAMMARAY_DISK_CRAWLER_EXT4_H
#define __GAMMARAY_DISK_CRAWLER_EXT4_H

/* Some struct definitions from Linux Kernel Source: http://goo.gl/dyM8I */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"

#define SECTOR_SIZE 512
#define EXT4_SUPERBLOCK_OFFSET 1024

struct ext4_superblock
{
    uint32_t s_inodes_count;
    uint32_t s_blocks_count_lo;
    uint32_t s_r_blocks_count_lo;
    uint32_t s_free_blocks_count_lo;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_cluster_size;
    uint32_t s_blocks_per_group;
    uint32_t s_clusters_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    uint8_t  s_volume_name[16];
    uint8_t  s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t s_reserved_gdt_blocks;
    uint8_t  s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;
    uint8_t  s_jnl_backup_type;
    uint16_t s_desc_size;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;
    uint32_t s_mkfs_time;
    uint32_t s_jnl_blocks[17];
    uint32_t s_blocks_count_hi;
    uint32_t s_r_blocks_count_hi;
    uint32_t s_free_blocks_count_hi;
    uint16_t s_min_extra_isize;
    uint16_t s_want_extra_isize;
    uint32_t s_flags;
    uint16_t s_raid_stride;
    uint16_t s_mmp_update_interval;
    uint64_t s_mmp_block;
    uint32_t s_raid_stripe_width;
    uint8_t  s_log_groups_per_flex;
    uint8_t  s_checksum_type;
    uint16_t s_reserved_pad;
    uint64_t s_kbytes_written;
    uint32_t s_snapshot_inum;
    uint32_t s_snapshot_id;
    uint64_t s_snapshot_r_blocks_count;
    uint32_t s_snapshot_list;
    uint32_t s_error_count;
    uint32_t s_first_error_time;
    uint32_t s_first_error_ino;
    uint64_t s_first_error_block;
    uint8_t  s_first_error_func[32];
    uint32_t s_first_error_line;
    uint32_t s_last_error_time;
    uint32_t s_last_error_ino;
    uint32_t s_last_error_line;
    uint64_t s_last_error_block;
    uint8_t  s_last_error_func[32];
    uint8_t  s_mount_opts[64];
    uint32_t s_usr_quota_inum;
    uint32_t s_grp_quota_inum;
    uint32_t s_overhead_clusters;
    uint32_t s_reserved[108];
    uint32_t s_checksum;
} __attribute__((packed));

struct ext4_block_group_descriptor
{
    uint32_t bg_block_bitmap_lo;        /* 00 */
    uint32_t bg_inode_bitmap_lo;
    uint32_t bg_inode_table_lo;
    uint16_t bg_free_blocks_count_lo;
    uint16_t bg_free_inodes_count_lo;   /* 10 */
    uint16_t bg_used_dirs_count_lo;
    uint16_t bg_flags;
    uint32_t bg_exclude_bitmap_lo;
    uint16_t bg_block_bitmap_csum_lo;
    uint16_t bg_inode_bitmap_csum_lo;
    uint16_t bg_itable_unused_lo;
    uint16_t bg_checksum;               /* 20 */
    /* enabled only on 64bit option set */
/*    uint32_t bg_block_bitmap_hi;
    uint32_t bg_inode_bitmap_hi;
    uint32_t bg_inode_table_hi;
    uint16_t bg_free_blocks_count_hi;
    uint16_t bg_free_inodes_count_hi;   * 30 */
 /*   uint16_t bg_used_dirs_count_hi;
    uint16_t bg_itable_unused_hi;
    uint32_t bg_exclude_bitmap_hi;
    uint16_t bg_block_bitmap_csum_hi;
    uint16_t bg_inode_bitmap_csum_hi;
    uint32_t bg_reserved;               * 3a */
} __attribute__((packed));

struct ext4_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size_lo;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks_lo;
    uint32_t i_flags;
    uint8_t  i_osd1[4];
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl_lo;
    uint32_t i_size_high;
    uint32_t i_obso_faddr;
    uint8_t  i_osd2[12];
    uint16_t i_extra_isize;
    uint16_t i_checksum_hi;
    uint32_t i_ctime_extra;
    uint32_t i_mtime_extra;
    uint32_t i_atime_extra;
    uint32_t i_crtime;
    uint32_t i_crtime_extra;
    uint32_t i_version_hi;
} __attribute__((packed));

struct ext4_dir_entry
{
    uint32_t inode;     /* 4 bytes */
    uint16_t rec_len;   /* 6 bytes */
    uint8_t name_len;   /* 7 bytes */
    uint8_t file_type;  /* 8 bytes */
    uint8_t name[255];  /* 263 bytes */
} __attribute__((packed));

struct ext4_extent_header
{
    uint16_t eh_magic;
    uint16_t eh_entries;
    uint16_t eh_max;
    uint16_t eh_depth;
    uint32_t eh_generation;
} __attribute__((packed));

struct ext4_extent_idx
{
    uint32_t ei_block;
    uint32_t ei_leaf_lo;
    uint16_t ei_leaf_hi;
    uint16_t ei_unused;
};

struct ext4_extent
{
    uint32_t ee_block;
    uint16_t ee_len;
    uint16_t ee_start_hi;
    uint32_t ee_start_lo;
};

uint64_t ext4_extent_start(struct ext4_extent extent);
uint64_t ext4_extent_index_leaf(struct ext4_extent_idx idx);
uint64_t ext4_file_size(struct ext4_inode inode);

int ext4_print_superblock(struct ext4_superblock superblock);
int ext4_print_features(struct ext4_superblock* superblock);
int ext4_print_block_group_descriptor(struct ext4_block_group_descriptor);
int ext4_print_inode(struct ext4_inode);
int ext4_print_dir_entries(uint8_t* bytes, uint32_t len);
int simple_find(uint32_t inode_table_location,
                FILE* disk, uint32_t inode, char* path_prefix);
int ext4_probe(FILE* disk, int64_t partition_offset,
               struct ext4_superblock* superblock);
int ext4_read_block(FILE* disk, int64_t partition_offset, 
                    struct ext4_superblock superblock, uint64_t block_num, 
                    uint8_t* buf);
int ext4_read_dir_entry(uint8_t* buf, struct ext4_dir_entry* dir);
int ext4_print_block(uint8_t* buf, uint32_t block_size);
uint64_t ext4_block_size(struct ext4_superblock superblock);
int ext4_print_sectormap(FILE* disk, int64_t partition_offset,
                         struct ext4_superblock superblock);
int64_t ext4_sector_from_block(uint64_t block, struct ext4_superblock super,
                               int64_t partition_offset);
char* ext4_last_mount_point(struct ext4_superblock* superblock);
uint64_t ext4_s_blocks_count(struct ext4_superblock superblock);
uint64_t ext4_bgd_block_bitmap(struct ext4_block_group_descriptor bgd);
uint64_t ext4_bgd_inode_bitmap(struct ext4_block_group_descriptor bgd);
uint64_t ext4_bgd_inode_table(struct ext4_block_group_descriptor bgd);
int ext4_serialize_fs(struct ext4_superblock* superblock, int64_t offset,
                      int32_t pte_num, struct bitarray* bits,
                      char* mount_point, FILE* serializef);
int ext4_serialize_bgds(FILE* disk, int64_t partition_offset,
                        struct ext4_superblock* superblock,
                        struct bitarray* bits, FILE* serializef,
                        uint8_t* bcache);
int ext4_serialize_fs_tree(FILE* disk, int64_t partition_offset,
                           struct ext4_superblock* superblock,
                           struct bitarray* bits, char* prefix,
                           FILE* serializef, uint8_t* icache,
                           uint8_t* bcache);
int ext4_serialize_journal(FILE* disk, int64_t partition_offset,
                            struct ext4_superblock* superblock,
                            struct bitarray* bits, char* mount,
                            FILE* serializef, uint8_t* icache,
                            uint8_t* bcache);
int ext4_cache_bgds(FILE* disk, int64_t partition_offset,
                    struct ext4_superblock* superblock, uint8_t** cache);
int ext4_cache_inodes(FILE* disk, int64_t partition_offset,
                      struct ext4_superblock* superblock, uint8_t** cache,
                      uint8_t* bcache);
#endif
