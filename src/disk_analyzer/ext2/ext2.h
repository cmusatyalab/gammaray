#ifndef XRAY_DISK_ANALYZER_EXT2_H
#define XRAY_DISK_ANALYZER_EXT2_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define SECTOR_SIZE 512
#define EXT2_SUPERBLOCK_OFFSET 1024

struct ext2_superblock
{
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count; 
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
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
    uint32_t s_algo_bitmap;
    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t alignment;
    uint8_t  s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;
    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;
    uint8_t  padding[3];
    uint32_t s_default_mount_options;
    uint32_t s_first_meta_bg;
} __attribute__((packed));

struct ext2_block_group_descriptor
{
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t  bg_reserved[12];
} __attribute__((packed));

struct ext2_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
} __attribute__((packed));

int ext2_print_superblock(struct ext2_superblock superblock);
int ext2_print_block_group_descriptor(struct ext2_block_group_descriptor);
int ext2_print_inode(struct ext2_inode);
int ext2_print_dir_entries(uint8_t* bytes, uint32_t len);
int simple_find(uint32_t inode_table_location,
                FILE* disk, uint32_t inode, char* path_prefix);
int ext2_probe(FILE* disk, int64_t partition_offset,
               struct ext2_superblock* superblock);
int ext3_probe(FILE* disk, int64_t partition_offset,
               struct ext2_superblock* superblock);
int ext2_read_inode(FILE* disk, int64_t partition_offset,
                    struct ext2_superblock superblock, uint32_t inode_num,
                    struct ext2_inode* inode);
int ext2_list_block_groups(FILE* disk, int64_t partition_offset,
                           struct ext2_superblock superblock);
int ext2_list_root_fs(FILE* disk, int64_t partition_offset,
                      struct ext2_superblock superblock, char* prefix);
int ext2_reconstruct_root_fs(FILE* disk, int64_t partition_offset, 
                             struct ext2_superblock superblock, char* prefix,
                             char* copy_prefix);
int ext2_read_block(FILE* disk, int64_t partition_offset, 
                    struct ext2_superblock superblock, uint64_t block_num, 
                    uint8_t* buf);
int ext2_print_block(uint8_t* buf, uint32_t block_size);
uint32_t ext2_block_size(struct ext2_superblock superblock);
int ext2_print_sectormap(FILE* disk, int64_t partition_offset,
                         struct ext2_superblock superblock);
int64_t ext2_sector_from_block(uint32_t block);
char* ext2_last_mount_point(struct ext2_superblock* superblock);
int ext2_serialize_fs(struct ext2_superblock* superblock,
                      char* mount_point, FILE* serializef);
int ext2_serialize_bgds(FILE* disk, int64_t partition_offset,
                        struct ext2_superblock* superblock, FILE* serializef);
int ext2_serialize_fs_tree(FILE* disk, int64_t partition_offset,
                           struct ext2_superblock* superblock, char* prefix,
                           FILE* serializef);
#endif
