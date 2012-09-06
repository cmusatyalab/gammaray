#define _FILE_OFFSET_BITS 64

#include "bson.h"
#include "mbr.h"
#include "ext4.h"
#include "util.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h> 
#include <sys/types.h>

/* for s_flags */
#define EXT2_FLAGS_TEST_FILESYS           0x0004

/* for s_feature_compat */
#define EXT3_FEATURE_COMPAT_HAS_JOURNAL         0x0004

/* for s_feature_ro_compat */
#define EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER     0x0001
#define EXT2_FEATURE_RO_COMPAT_LARGE_FILE 0x0002
#define EXT2_FEATURE_RO_COMPAT_BTREE_DIR  0x0004
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE  0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM         0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK  0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE      0x0040

/* for s_feature_incompat */
#define EXT2_FEATURE_INCOMPAT_FILETYPE          0x0002
#define EXT3_FEATURE_INCOMPAT_RECOVER           0x0004
#define EXT3_FEATURE_INCOMPAT_JOURNAL_DEV 0x0008
#define EXT2_FEATURE_INCOMPAT_META_BG           0x0010
#define EXT4_FEATURE_INCOMPAT_EXTENTS           0x0040 /* extents support */
#define EXT4_FEATURE_INCOMPAT_64BIT       0x0080
#define EXT4_FEATURE_INCOMPAT_MMP         0x0100
#define EXT4_FEATURE_INCOMPAT_FLEX_BG           0x0200

#define EXT2_FEATURE_RO_COMPAT_SUPP (EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER| \
                                       EXT2_FEATURE_RO_COMPAT_LARGE_FILE| \
                                       EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
#define EXT2_FEATURE_INCOMPAT_SUPP  (EXT2_FEATURE_INCOMPAT_FILETYPE| \
                                       EXT2_FEATURE_INCOMPAT_META_BG)
#define EXT2_FEATURE_INCOMPAT_UNSUPPORTED ~EXT2_FEATURE_INCOMPAT_SUPP
#define EXT2_FEATURE_RO_COMPAT_UNSUPPORTED      ~EXT2_FEATURE_RO_COMPAT_SUPP

#define EXT3_FEATURE_RO_COMPAT_SUPP (EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER| \
                                       EXT2_FEATURE_RO_COMPAT_LARGE_FILE| \
                                       EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
#define EXT3_FEATURE_INCOMPAT_SUPP  (EXT2_FEATURE_INCOMPAT_FILETYPE| \
                                       EXT3_FEATURE_INCOMPAT_RECOVER| \
                                       EXT2_FEATURE_INCOMPAT_META_BG)
#define EXT3_FEATURE_INCOMPAT_UNSUPPORTED ~EXT3_FEATURE_INCOMPAT_SUPP
#define EXT3_FEATURE_RO_COMPAT_UNSUPPORTED      ~EXT3_FEATURE_RO_COMPAT_SUPP

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

char* ext4_s_creator_os_LUT[] = {
                                "EXT4_OS_LINUX","EXT4_OS_HURD","EXT4_OS_MASIX",
                                "EXT4_OS_FREEBSD","EXT4_OS_LITES"
                           };

char* ext4_s_rev_level_LUT[] = {
                                "EXT4_GOOD_OLD_REV","EXT4_DYNAMIC_REV"
                          };

char* ext4_s_state_LUT[] = {
                                "","EXT4_VALID_FS","EXT4_ERROR_FS","",
                                "EXT4_ORPHAN_FS"
                      };

char* ext4_s_errors_LUT[] = {
                                "","EXT4_ERRORS_CONTINUE","EXT4_ERRORS_RO",
                                "EXT4_ERRORS_PANIC"
                       };

int ext4_print_block(uint8_t* buf, uint32_t block_size)
{
    hexdump(buf, block_size); 
    return 0;
}

uint64_t ext4_s_blocks_count(struct ext4_superblock superblock)
{
    uint32_t s_blocks_count_lo = superblock.s_blocks_count_lo;
    uint32_t s_blocks_count_hi = superblock.s_blocks_count_hi;

    return (((uint64_t) s_blocks_count_hi) << 32) | s_blocks_count_lo;
}

uint64_t ext4_s_r_blocks_count(struct ext4_superblock superblock)
{
    uint32_t s_r_blocks_count_lo = superblock.s_r_blocks_count_lo;
    uint32_t s_r_blocks_count_hi = superblock.s_r_blocks_count_hi;

    return (((uint64_t) s_r_blocks_count_hi) << 32) | s_r_blocks_count_lo;
}

uint64_t ext4_s_free_blocks_count(struct ext4_superblock superblock)
{
    uint32_t s_free_blocks_count_lo = superblock.s_free_blocks_count_lo;
    uint32_t s_free_blocks_count_hi = superblock.s_free_blocks_count_hi;

    return (((uint64_t) s_free_blocks_count_hi) << 32) | s_free_blocks_count_lo;
}

int ext4_print_features(struct ext4_superblock* superblock)
{

    if (superblock->s_feature_ro_compat & EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)
        fprintf_yellow(stdout, "\tEXT2_FEATURE_RO_COMPAT_SPARSE_SUPER\n");

    if (superblock->s_feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL)
        fprintf_yellow(stdout, "\tEXT3_FEATURE_COMPAT_HAS_JOURNAL\n");

    if (superblock->s_feature_ro_compat & EXT2_FEATURE_RO_COMPAT_LARGE_FILE)
        fprintf_yellow(stdout, "\tEXT2_FEATURE_RO_COMPAT_LARGE_FILE\n");
    if (superblock->s_feature_ro_compat & EXT2_FEATURE_RO_COMPAT_BTREE_DIR)
        fprintf_yellow(stdout, "\tEXT2_FEATURE_RO_COMPAT_BTREE_DIR\n");
    if (superblock->s_feature_ro_compat & EXT4_FEATURE_RO_COMPAT_HUGE_FILE)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_RO_COMPAT_HUGE_FILE\n");
    if (superblock->s_feature_ro_compat & EXT4_FEATURE_RO_COMPAT_GDT_CSUM)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_RO_COMPAT_GDT_CSUM\n");
    if (superblock->s_feature_ro_compat & EXT4_FEATURE_RO_COMPAT_DIR_NLINK)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_RO_COMPAT_DIR_NLINK\n");
    if (superblock->s_feature_ro_compat & EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE\n");

    if (superblock->s_feature_incompat & EXT2_FEATURE_INCOMPAT_FILETYPE)
        fprintf_yellow(stdout, "\tEXT2_FEATURE_INCOMPAT_FILETYPE\n");

    if (superblock->s_feature_incompat & EXT3_FEATURE_INCOMPAT_RECOVER)
        fprintf_yellow(stdout, "\tEXT3_FEATURE_INCOMPAT_RECOVER\n");
    if (superblock->s_feature_incompat & EXT3_FEATURE_INCOMPAT_JOURNAL_DEV)
        fprintf_yellow(stdout, "\tEXT3_FEATURE_INCOMPAT_JOURNAL_DEV\n");
    if (superblock->s_feature_incompat & EXT2_FEATURE_INCOMPAT_META_BG)
        fprintf_yellow(stdout, "\tEXT2_FEATURE_INCOMPAT_META_BG\n");
    if (superblock->s_feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_INCOMPAT_EXTENTS\n");
    if (superblock->s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_INCOMPAT_64BIT\n");
    if (superblock->s_feature_incompat & EXT4_FEATURE_INCOMPAT_MMP)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_INCOMPAT_MMP\n");
    if (superblock->s_feature_incompat & EXT4_FEATURE_INCOMPAT_FLEX_BG)
        fprintf_yellow(stdout, "\tEXT4_FEATURE_INCOMPAT_FLEX_BG\n");
    return EXIT_SUCCESS;
}

int ext4_print_superblock(struct ext4_superblock superblock)
{
    fprintf_yellow(stdout, "s_inodes_count: %"PRIu32"\n",
                           superblock.s_inodes_count);
    fprintf_yellow(stdout, "s_blocks_count: %"PRIu64"\n",
                           ext4_s_blocks_count(superblock));
    fprintf_yellow(stdout, "s_r_blocks_count: %"PRIu32"\n",
                           ext4_s_r_blocks_count(superblock));
    fprintf_yellow(stdout, "s_free_blocks_count: %"PRIu32"\n",
                           ext4_s_free_blocks_count(superblock));
    fprintf_yellow(stdout, "s_free_inodes_count: %"PRIu32"\n",
                           superblock.s_free_inodes_count);
    fprintf_yellow(stdout, "s_first_data_block: %"PRIu32"\n",
                           superblock.s_first_data_block);
    fprintf_yellow(stdout, "s_log_block_size: %"PRIu32"\n",
                           superblock.s_log_block_size);
    fprintf_yellow(stdout, "s_log_cluster_size: %"PRIu32"\n",
                           superblock.s_log_cluster_size);
    fprintf_yellow(stdout, "s_blocks_per_group: %"PRIu32"\n",
                           superblock.s_blocks_per_group);
    fprintf_yellow(stdout, "s_clusters_per_group: %"PRIu32"\n",
                           superblock.s_clusters_per_group);
    fprintf_yellow(stdout, "s_inodes_per_group: %"PRIu32"\n",
                           superblock.s_inodes_per_group);
    fprintf_yellow(stdout, "s_mtime: %"PRIu32"\n",
                           superblock.s_mtime);
    fprintf_yellow(stdout, "s_wtime: %"PRIu32"\n",
                           superblock.s_wtime);
    fprintf_yellow(stdout, "s_mnt_count: %"PRIu16"\n",
                           superblock.s_mnt_count);
    fprintf_yellow(stdout, "s_max_mnt_count: %"PRIu16"\n",
                           superblock.s_max_mnt_count);
    fprintf_yellow(stdout, "s_magic: %"PRIx16"\n",
                           superblock.s_magic);
    if (superblock.s_magic == 0xef53)
    {
        fprintf_light_green(stdout, "Magic value matches EXT4_SUPER_MAGIC\n"); 
    }
    else
    {
        fprintf_light_red(stdout,
                          "Magic value does not match EXT4_SUPER_MAGIC\n");
    }
    fprintf_yellow(stdout, "s_state: %"PRIu16"\n",
                           superblock.s_state);
    fprintf_light_yellow(stdout, "File System State: %s\n",
                                 ext4_s_state_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_errors: %"PRIu16"\n",
                           superblock.s_errors);
    fprintf_light_yellow(stdout, "Error State: %s\n",
                                 ext4_s_errors_LUT[superblock.s_errors]);
    fprintf_yellow(stdout, "s_minor_rev_level: %"PRIu16"\n",
                           superblock.s_minor_rev_level);
    fprintf_yellow(stdout, "s_lastcheck: %"PRIu32"\n",
                           superblock.s_lastcheck);
    fprintf_yellow(stdout, "s_checkinterval: %"PRIu32"\n",
                           superblock.s_checkinterval);
    fprintf_yellow(stdout, "s_creator_os: %"PRIu32"\n",
                           superblock.s_creator_os);
    fprintf_light_yellow(stdout, "Resolved OS: %s\n",
                                 ext4_s_creator_os_LUT[superblock.s_creator_os]);
    fprintf_yellow(stdout, "s_rev_level: %"PRIu32"\n",
                           superblock.s_rev_level);
    fprintf_light_yellow(stdout, "Revision Level: %s\n",
                                 ext4_s_rev_level_LUT[superblock.s_rev_level]);
    fprintf_yellow(stdout, "s_def_resuid: %"PRIu16"\n",
                           superblock.s_def_resuid);
    fprintf_yellow(stdout, "s_def_resgid: %"PRIu16"\n",
                           superblock.s_def_resgid);
    fprintf_yellow(stdout, "s_first_ino: %"PRIu32"\n",
                           superblock.s_first_ino);
    fprintf_yellow(stdout, "s_inode_size: %"PRIu16"\n",
                           superblock.s_inode_size);
    fprintf_yellow(stdout, "s_block_group_nr: %"PRIu16"\n",
                           superblock.s_block_group_nr);
    fprintf_yellow(stdout, "s_feature_compat: %"PRIu32"\n",
                          superblock.s_feature_compat);
    fprintf_yellow(stdout, "s_feature_incompat: %"PRIu32"\n",
                           superblock.s_feature_incompat);
    fprintf_yellow(stdout, "s_feature_ro_compat: %"PRIu32"\n",
                           superblock.s_feature_ro_compat);
    //uint8_t s_uuid[16];
    //uint8_t s_volume_name[16];
    fprintf_light_yellow(stdout, "Last mounted as: '%s'\n",
                                superblock.s_last_mounted);
    //uint8_t s_last_mounted[64];
    fprintf_yellow(stdout, "s_algorithm_usage_bitmap: %"PRIu32"\n",
                           superblock.s_algorithm_usage_bitmap);
    fprintf_yellow(stdout, "s_prealloc_blocks: %"PRIu8"\n",
    superblock.s_prealloc_blocks);                       
    fprintf_yellow(stdout, "s_prealloc_blocks: %"PRIu8"\n",
                           superblock.s_prealloc_blocks);
    //uint8_t alignment[2];
    //uint8_t s_journal_uuid[16];
    fprintf_yellow(stdout, "s_journal_inum: %"PRIu32"\n",
                           superblock.s_journal_inum);
    fprintf_yellow(stdout, "s_journal_dev: %"PRIu32"\n",
                           superblock.s_journal_dev);
    fprintf_yellow(stdout, "s_last_orphan: %"PRIu32"\n",
                           superblock.s_last_orphan);
    //uint32_t s_hash_seed[4];
    fprintf_yellow(stdout, "s_def_hash_version: %"PRIu8"\n",
                           superblock.s_def_hash_version);  
    //uint8_t padding[3];
    fprintf_yellow(stdout, "s_default_mount_options: %"PRIu32"\n",
                           superblock.s_default_mount_opts);
    fprintf_yellow(stdout, "s_first_meta_bg: %"PRIu32"\n",
                           superblock.s_first_meta_bg);
    fprintf_yellow(stdout, "s_mkfs_time: %"PRIu32"\n", superblock.s_mkfs_time);
    fprintf_yellow(stdout, "s_log_groups_per_flex: %"PRIu8"\n",
                            superblock.s_log_groups_per_flex);
    return 0;
}


uint64_t ext4_block_size(struct ext4_superblock superblock)
{
    return ((uint64_t) 1024) << superblock.s_log_block_size;
}

uint64_t ext4_num_block_groups(struct ext4_superblock superblock)
{
    uint64_t blocks = ext4_s_blocks_count(superblock);
    uint64_t blocks_per_group = superblock.s_blocks_per_group;

    return (blocks + blocks_per_group - 1) / blocks_per_group;
}

uint32_t ext4_next_block_group_descriptor(FILE* disk,
                                     int64_t partition_offset,
                                     struct ext4_superblock superblock,
                                     struct ext4_block_group_descriptor* bgd)
{
    static uint32_t i = 0;
    uint64_t offset = (superblock.s_first_data_block+1) *
                      ext4_block_size(superblock);
    uint64_t num_block_groups = ext4_num_block_groups(superblock);

    for (; i < num_block_groups;)
    {
        if (fseeko(disk, partition_offset + offset +
                         (i) *
                         sizeof(struct ext4_block_group_descriptor), 0))
        {
            fprintf_light_red(stderr, "error seeking to position 0x%lx.\n",
                              offset);
            return 0;
        }

        if (fread(bgd, 1, sizeof(struct ext4_block_group_descriptor), disk) !=
            sizeof(struct ext4_block_group_descriptor))
        {
            fprintf_light_red(stderr, 
                              "error while trying to read ext4 block group "
                              "descriptor.\n");
            return 0;
        }
        i++;
        return (partition_offset + offset + i*sizeof(struct ext4_block_group_descriptor)) / SECTOR_SIZE;
    }

    return 0; 
}

int ext4_next_block_group_descriptor_sectors(FILE* disk,
                                             int64_t partition_offset,
                                             struct ext4_superblock superblock,
                                             struct ext4_block_group_descriptor* bgd)
{
    static uint32_t i = 0;
    uint64_t offset = (superblock.s_first_data_block+1) * ext4_block_size(superblock);
    uint32_t num_block_groups = ext4_num_block_groups(superblock);

    for (; i < num_block_groups;)
    {
        if (fseeko(disk, partition_offset + offset + i*sizeof(struct ext4_block_group_descriptor), 0))
        {
            fprintf_light_red(stderr, "error seeking to position 0x%lx.\n",
                              offset);
            return -1;
        }

        if (fread(bgd, 1, sizeof(struct ext4_block_group_descriptor), disk) !=
            sizeof(struct ext4_block_group_descriptor))
        {
            fprintf_light_red(stderr, 
                              "Error while trying to read ext4 block group "
                              "descriptor.\n");
            return -1;
        }
        fprintf_yellow(stdout, "BGD %"PRIu32"\nstart sector %"PRIu64"\n",
                               i, offset / SECTOR_SIZE);
        i++;
        return 1;
    }

    return 0; 
}

int ext4_write_block(FILE* dest, uint32_t total_size, uint32_t block_size,
                uint8_t* buf)
{
    if (total_size <= block_size)
    {
        if (fwrite(buf, 1, total_size, dest) != total_size)
        {
            fprintf_light_red(stderr, "Error writing to destination file."
                                      "\n");
            return -1;
        }
        return 0;
    }
    else
    {
        if (fwrite(buf, 1, block_size, dest) != block_size)
        {
            fprintf_light_red(stderr, "Error writing to destination file."
                                      "\n");
            return -1;
        }
        total_size -= block_size;
    }
    return total_size;
}

int ext4_print_dir_entry(uint32_t entry, struct ext4_dir_entry dir)
{
    fprintf_yellow(stdout, "%d ext4_dir_entry.inode: %"PRIu32"\n", entry,
                           dir.inode);
    fprintf_yellow(stdout, "%d ext4_dir_entry.rec_len: %"PRIu16"\n", entry,
                           dir.rec_len);
    fprintf_yellow(stdout, "%d ext4_dir_entry.name_len: %"PRIu8"\n", entry,
                           dir.name_len);
    if (dir.name_len < 256)
        dir.name[dir.name_len] = '\0';
    else
        dir.name[0] = '\0';
    fprintf_yellow(stdout, "%d ext4_dir_entry.name: %s\n", entry, dir.name);
    fprintf(stdout, "\n\n");
    return 0;
} 

int ext4_print_dir_entries(uint8_t* bytes, uint32_t len)
{
    uint32_t i;
    uint32_t num_entries = len / sizeof(struct ext4_dir_entry);

    for (i = 0; i < num_entries; i++)
        ext4_print_dir_entry(i, *((struct ext4_dir_entry*)
                                  (bytes + i*sizeof(struct ext4_dir_entry))));
    return 0;
}

mode_t ext4_inode_mode(uint16_t i_mode)
{
    mode_t mode = 0;

    /* file format */
    if ((i_mode & 0xc000) == 0xc000)
        mode |= S_IFSOCK;
    if ((i_mode & 0xa000) == 0xa000)
        mode |= S_IFLNK;
    if (i_mode & 0x8000)
        mode |= S_IFREG;
    if ((i_mode & 0x6000) == 0x6000)
        mode |= S_IFBLK;
    if (i_mode & 0x4000)
        mode |= S_IFDIR;
    if (i_mode & 0x2000)
        mode |= S_IFCHR;
    if (i_mode & 0x1000)
        mode |= S_IFIFO;

    /* process execution/group override */
    if (i_mode & 0x0800)
        mode |= S_ISUID;
    if (i_mode & 0x0400)
        mode |= S_ISGID;
    if (i_mode & 0x0200)
        mode |= S_ISVTX;

    /* access control */
    if (i_mode & 0x0100)
        mode |= S_IRUSR;
    if (i_mode & 0x0080)
        mode |= S_IWUSR;
    if (i_mode & 0x0040)
        mode |= S_IXUSR;
    if (i_mode & 0x0020)
        mode |= S_IRGRP;
    if (i_mode & 0x0010)
        mode |= S_IWGRP;
    if (i_mode & 0x0008)
        mode |= S_IXGRP;
    if (i_mode & 0x0004)
        mode |= S_IROTH;
    if (i_mode & 0x0002)
        mode |= S_IWOTH;
    if (i_mode & 0x0001)
        mode |= S_IXOTH;
    return mode;
}

uint64_t ext4_block_offset(uint64_t block_num, struct ext4_superblock superblock)
{
    uint64_t block_size = ext4_block_size(superblock);
    return block_size * block_num;
}

int ext4_read_block(FILE* disk, int64_t partition_offset, 
                    struct ext4_superblock superblock, uint64_t block_num, 
                    uint8_t* buf)
{
    uint64_t block_size = ext4_block_size(superblock);
    uint64_t offset = ext4_block_offset(block_num, superblock);
    offset += partition_offset;

    if (fseeko(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error while reading block seeking to position 0x%lx.\n", 
                                  offset);
        return -1;
    }

    if (fread(buf, 1, block_size, disk) != block_size)
    {
        fprintf_light_red(stderr, "Error while trying to read block.\n");
        return -1;
    }

    return 0;

}

uint32_t ext4_bgd_free_blocks_count(struct ext4_block_group_descriptor bgd)
{
    uint16_t bg_free_blocks_count_lo = bgd.bg_free_blocks_count_lo;
    uint16_t bg_free_blocks_count_hi = 0;
    return ((uint32_t) bg_free_blocks_count_hi << 16) | bg_free_blocks_count_lo;
}

uint32_t ext4_bgd_free_inodes_count(struct ext4_block_group_descriptor bgd)
{
    uint16_t bg_free_inodes_count_lo = bgd.bg_free_inodes_count_lo;
    uint16_t bg_free_inodes_count_hi = 0;
    return ((uint32_t) bg_free_inodes_count_hi << 16) | bg_free_inodes_count_lo;
}

uint32_t ext4_bgd_used_dirs_count(struct ext4_block_group_descriptor bgd)
{
    uint16_t bg_used_dirs_count_lo = bgd.bg_used_dirs_count_lo;
    uint16_t bg_used_dirs_count_hi = 0;
    return ((uint32_t) bg_used_dirs_count_hi << 16) | bg_used_dirs_count_lo;
}

uint64_t ext4_bgd_block_bitmap(struct ext4_block_group_descriptor bgd)
{
    uint32_t bg_block_bitmap_lo = bgd.bg_block_bitmap_lo;
    uint32_t bg_block_bitmap_hi = 0;
    return ((uint64_t) bg_block_bitmap_hi << 32) | bg_block_bitmap_lo;
}

uint64_t ext4_bgd_inode_bitmap(struct ext4_block_group_descriptor bgd)
{
    uint32_t bg_inode_bitmap_lo = bgd.bg_inode_bitmap_lo;
    uint32_t bg_inode_bitmap_hi = 0;
    return ((uint64_t) bg_inode_bitmap_hi << 32) | bg_inode_bitmap_lo;
}

uint64_t ext4_bgd_inode_table(struct ext4_block_group_descriptor bgd)
{
    uint32_t bg_inode_table_lo = bgd.bg_inode_table_lo;
    uint32_t bg_inode_table_hi = 0;
    return ((uint64_t) bg_inode_table_hi << 32) | bg_inode_table_lo;
}

int ext4_read_bgd(FILE* disk, int64_t partition_offset,
                 struct ext4_superblock superblock,
                 uint32_t block_group,
                 struct ext4_block_group_descriptor* bgd)
{
    uint64_t offset = (superblock.s_first_data_block+1) *
                      ext4_block_size(superblock) +
                      block_group*sizeof(struct ext4_block_group_descriptor);

    if (fseeko(disk, partition_offset + offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
        return -1;
    }

    if (fread(bgd, 1, sizeof(struct ext4_block_group_descriptor), disk) !=
        sizeof(struct ext4_block_group_descriptor))
    {
        fprintf_light_red(stderr, 
                          "Error while trying to read ext4 Block Group "
                          "Descriptor.\n");
        return -1;
    }

    return 0;
}

int ext4_read_inode_serialized(FILE* disk, int64_t partition_offset,
                               struct ext4_superblock superblock,
                               uint32_t inode_num, struct ext4_inode* inode,
                               struct bson_info* bson)
{
    uint64_t block_group = (inode_num - 1) / superblock.s_inodes_per_group;
    struct ext4_block_group_descriptor bgd;
    uint64_t inode_table_offset;
    uint64_t inode_offset = (inode_num - 1) % superblock.s_inodes_per_group;
    inode_offset *= superblock.s_inode_size;
    struct bson_kv val;
    uint64_t sector, offset;

    if (ext4_read_bgd(disk, partition_offset, superblock, block_group, &bgd))
    {
        fprintf(stderr, "Error retrieving block group descriptor %"PRIu64".\n", block_group);
        return -1;
    }

    inode_table_offset = ext4_block_offset(ext4_bgd_inode_table(bgd), superblock);

    if (fseeko(disk, partition_offset + inode_table_offset + inode_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                                  partition_offset + inode_table_offset +
                                  inode_offset);
        return -1;
    }

    if (fread(inode, 1, sizeof(struct ext4_inode), disk) != sizeof(struct ext4_inode))
    {
        fprintf_light_red(stdout, "Error while trying to read ext4 inode.\n");
        return -1;
    }

    sector = (partition_offset + inode_table_offset + inode_offset) /
             SECTOR_SIZE;
    val.type = BSON_INT64;
    val.key = "inode_sector";
    val.data = &sector;

    bson_serialize(bson, &val);

    offset = (partition_offset + inode_table_offset + inode_offset) %
             SECTOR_SIZE;
    val.type = BSON_INT64;
    val.key = "inode_offset";
    val.data = &offset;

    bson_serialize(bson, &val);

    return 0;
}

int ext4_read_inode(FILE* disk, int64_t partition_offset,
                    struct ext4_superblock superblock,
                    uint32_t inode_num, struct ext4_inode* inode)
{
    uint64_t block_group = (inode_num - 1) / superblock.s_inodes_per_group;
    struct ext4_block_group_descriptor bgd;
    uint64_t inode_table_offset;
    uint64_t inode_offset = (inode_num - 1) % superblock.s_inodes_per_group;
    inode_offset *= superblock.s_inode_size;

    if (ext4_read_bgd(disk, partition_offset, superblock, block_group, &bgd))
    {
        fprintf(stderr, "Error retrieving block group descriptor %"PRIu64".\n", block_group);
        return -1;
    }

    inode_table_offset = ext4_block_offset(ext4_bgd_inode_table(bgd), superblock);

    if (fseeko(disk, partition_offset + inode_table_offset + inode_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                                  partition_offset + inode_table_offset +
                                  inode_offset);
        return -1;
    }

    if (fread(inode, 1, sizeof(struct ext4_inode), disk) != sizeof(struct ext4_inode))
    {
        fprintf_light_red(stdout, "Error while trying to read ext4 inode.\n");
        return -1;
    }

    return 0;
}

int64_t ext4_sector_from_block(uint64_t block, struct ext4_superblock super,
                               int64_t partition_offset)
{
    return (block * ext4_block_size(super) + partition_offset) / SECTOR_SIZE;
}

int ext4_print_extent_header(struct ext4_extent_header hdr)
{
    fprintf_yellow(stdout, "eh_magic: 0x%0.4"PRIx16"\n", hdr.eh_magic);
    
    if (hdr.eh_magic == 0xf30a)
        fprintf_light_blue(stdout, "\teh_magic MATCHES.\n");
    else
    {
        fprintf_light_red(stdout, "\teh_magic DOES NOT MATCH.\n");
    }

    fprintf_yellow(stdout, "eh_entries: %"PRIu16"\n", hdr.eh_entries);
    fprintf_yellow(stdout, "eh_max: %"PRIu16"\n", hdr.eh_max);
    fprintf_yellow(stdout, "eh_depth: %"PRIu16"\n", hdr.eh_depth);
    fprintf_yellow(stdout, "eh_generation: %"PRIu32"\n", hdr.eh_generation);
    return EXIT_SUCCESS;
}

uint64_t ext4_extent_start(struct ext4_extent extent)
{
    uint64_t start = (uint64_t) extent.ee_start_hi << 48;
    return start | extent.ee_start_lo;
}

int ext4_print_extent(struct ext4_extent extent)
{
    fprintf_light_yellow(stdout, "ee_block: %"PRIu32"\n", extent.ee_block);
    fprintf_yellow(stdout, "ee_len: %"PRIu16"\n", extent.ee_len);
    fprintf_yellow(stdout, "ee_start: %"PRIu64"\n", ext4_extent_start(extent));
    return EXIT_SUCCESS;
}

uint64_t ext4_extent_index_leaf(struct ext4_extent_idx idx)
{
    uint64_t leaf = (uint64_t) idx.ei_leaf_hi << 48;
    return leaf | idx.ei_leaf_lo;
}

int ext4_print_extent_index(struct ext4_extent_idx idx)
{
    fprintf_light_yellow(stdout, "ei_block: %"PRIu32"\n", idx.ei_block);
    fprintf_yellow(stdout, "ei_leaf: %"PRIu64"\n",
                           ext4_extent_index_leaf(idx));
    return EXIT_SUCCESS;
}

int ext4_read_extent_block(FILE* disk, int64_t partition_offset,
                           struct ext4_superblock superblock, uint32_t block_num,
                           struct ext4_inode inode, uint8_t* buf)
{
    int i;
    struct ext4_extent_header hdr; 
    struct ext4_extent_idx idx;
    struct ext4_extent_idx idx2; /* lookahead when searching for block_num */
    struct ext4_extent extent;

    memcpy(buf, inode.i_block, (size_t) 60);
    hdr = *((struct ext4_extent_header*) buf);
    idx.ei_block = (uint32_t) 2 << 31;

    for (i = 0; i < hdr.eh_entries; i++)
    {
        if (hdr.eh_depth)
        {
            /* TODO */
            idx2 =  * ((struct ext4_extent_idx*)
                            &(buf[sizeof(struct ext4_extent_header) +
                                  sizeof(struct ext4_extent_idx)*i])); 
            if (hdr.eh_entries == 1)
            {
                ext4_read_block(disk, partition_offset, superblock,
                                ext4_extent_index_leaf(idx2), buf);
                i = -1; /* allow loop-expr to run (++) */
                hdr = *((struct ext4_extent_header*) buf);
                idx.ei_block = (uint32_t) 2 << 31;
                continue;
            }

            if ((block_num < idx2.ei_block &&
                block_num >= idx.ei_block))
            {
                ext4_read_block(disk, partition_offset, superblock,
                                ext4_extent_index_leaf(idx), buf);
                i = -1; /* allow loop-expr to run (++) */
                hdr = *((struct ext4_extent_header*) buf);
                idx.ei_block = (uint32_t) 2 << 31;
                continue;
            }
            idx = idx2;
        }
        else
        {
            extent = * ((struct ext4_extent*)
                            &(buf[sizeof(struct ext4_extent_header) +
                                  sizeof(struct ext4_extent)*i])); 
            if (extent.ee_block <= block_num &&
                block_num < extent.ee_block + extent.ee_len)
            {
                block_num -= extent.ee_block; /* rebase */
                ext4_read_block(disk, partition_offset, superblock,
                                ext4_extent_start(extent) + block_num,
                                (uint8_t*) buf);
                return 0;
            }
        }
    }

    memset(buf, 0, (size_t) ext4_block_size(superblock)); /* assuming hole */
    return 0; 
}

int ext4_read_file_block(FILE* disk, int64_t partition_offset,
                         struct ext4_superblock superblock, uint64_t block_num,
                         struct ext4_inode inode, uint32_t* buf)
{
    fprintf_light_blue(stderr, "in ext4_read_file_block, block_num = %"PRIu64"\n", block_num);
    uint64_t block_size = ext4_block_size(superblock);
    uint64_t addresses_in_block = block_size / 4;
    
    /* ranges for lookup */
    uint64_t direct_low = 0;
    uint64_t direct_high = 11;
    uint64_t indirect_low = direct_high + 1;
    uint64_t indirect_high = direct_high + (addresses_in_block);
    uint64_t double_low = indirect_high + 1;
    uint64_t double_high = indirect_high + (addresses_in_block)*
                                           (addresses_in_block);
    uint64_t triple_low = double_high + 1;
    uint64_t triple_high = double_high + (addresses_in_block)*
                                         (addresses_in_block)*
                                         (addresses_in_block);

    if (block_num < direct_low || block_num > triple_high)
    {
        fprintf_light_red(stderr, "File block outside of range of inode.\n");
        return -1;
    }

    /* figure out type of block lookup (direct, indirect, double, treble) */
    /* DIRECT */
    if (block_num <= direct_high)
    {
        if (inode.i_block[block_num] == 0)
            return 1; /* finished */
        ext4_read_block(disk, partition_offset, superblock,
                        inode.i_block[block_num], (uint8_t*) buf);
        return 0;
    }

    /* INDIRECT */
    if (block_num <= indirect_high)
    {
        block_num -= indirect_low; /* rebase, 0 is beginning indirect block range */
        
        if (inode.i_block[12] == 0)
            return 1; /* finished */

        ext4_read_block(disk, partition_offset, superblock, inode.i_block[12],
                        (uint8_t*) buf);

        if (buf[block_num] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, superblock, buf[block_num],
                        (uint8_t*) buf);
        return 0;
    }

    /* DOUBLE */
    if (block_num <= double_high)
    {
        block_num -= double_low;

        if (inode.i_block[13] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* double */
                        superblock, inode.i_block[13], (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],
                        (uint8_t*) buf);

        return 0;
    }

    /* TRIPLE */
    if (block_num <= triple_high)
    {
        block_num -= triple_low;

        if (inode.i_block[14] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* triple */
                        superblock, inode.i_block[14], (uint8_t*) buf);

        if (buf[block_num / (addresses_in_block*addresses_in_block)] == 0)
            return 1;
        
        ext4_read_block(disk, partition_offset, /* double */
                        superblock,
                        buf[block_num / (addresses_in_block*addresses_in_block)],
                        (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],  
                        (uint8_t*) buf);

        return 0;
    }

    return -1;
}

int ext4_read_file_block_sectors(FILE* disk, int64_t partition_offset,
                                 struct ext4_superblock superblock, uint64_t block_num,
                                 struct ext4_inode inode, uint32_t* buf)
{
    uint64_t block_size = ext4_block_size(superblock);
    uint64_t addresses_in_block = block_size / 4;
    
    /* ranges for lookup */
    uint64_t direct_low = 0;
    uint64_t direct_high = 11;
    uint64_t indirect_low = direct_high + 1;
    uint64_t indirect_high = direct_high + (addresses_in_block);
    uint64_t double_low = indirect_high + 1;
    uint64_t double_high = indirect_high + (addresses_in_block)*
                                           (addresses_in_block);
    uint64_t triple_low = double_high + 1;
    uint64_t triple_high = double_high + (addresses_in_block)*
                                         (addresses_in_block)*
                                         (addresses_in_block);

    if (block_num < direct_low || block_num > triple_high)
    {
        fprintf_light_red(stderr, "File block outside of range of inode.\n");
        return -1;
    }

    /* figure out type of block lookup (direct, indirect, double, treble) */
    /* DIRECT */
    if (block_num <= direct_high)
    {
        if (inode.i_block[block_num] == 0)
            return 1; /* finished */

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (inode.i_block[block_num] *
                                ext4_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext4_read_block(disk, partition_offset, superblock,
                        inode.i_block[block_num], (uint8_t*) buf);
        return 0;
    }

    /* INDIRECT */
    if (block_num <= indirect_high)
    {
        block_num -= indirect_low; /* rebase, 0 is beginning indirect block range */
        
        if (inode.i_block[12] == 0)
            return 1; /* finished */

        ext4_read_block(disk, partition_offset, superblock, inode.i_block[12],
                        (uint8_t*) buf);

        if (buf[block_num] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num] *
                                ext4_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext4_read_block(disk, partition_offset, superblock, buf[block_num],
                        (uint8_t*) buf);
        return 0;
    }

    /* DOUBLE */
    if (block_num <= double_high)
    {
        block_num -= double_low;

        if (inode.i_block[13] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* double */
                        superblock, inode.i_block[13], (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num % addresses_in_block] *
                                ext4_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext4_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],
                        (uint8_t*) buf);

        return 0;
    }

    /* TRIPLE */
    if (block_num <= triple_high)
    {
        block_num -= triple_low;

        if (inode.i_block[14] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* triple */
                        superblock, inode.i_block[14], (uint8_t*) buf);

        if (buf[block_num / (addresses_in_block*addresses_in_block)] == 0)
            return 1;
        
        ext4_read_block(disk, partition_offset, /* double */
                        superblock,
                        buf[block_num / (addresses_in_block*addresses_in_block)],
                        (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num % addresses_in_block] *
                                ext4_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext4_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],  
                        (uint8_t*) buf);

        return 0;
    }

    return -1;
}

int ext4_read_dir_entry(uint8_t* buf, struct ext4_dir_entry* dir)
{
    memcpy(dir, buf, sizeof(struct ext4_dir_entry));
    return 0;
}

uint64_t ext4_file_size(struct ext4_inode inode)
{
    uint64_t total_size = ((uint64_t) inode.i_size_high) << 32;
    total_size |= inode.i_size_lo;
    return total_size;
}

/* recursive function listing a tree rooted at some directory.
 * recursion ends at leaf files.
 * depth-first
 */
int ext4_list_tree(FILE* disk, int64_t partition_offset, 
                   struct ext4_superblock superblock,
                   struct ext4_inode root_inode,
                   char* prefix)
{
    struct ext4_inode child_inode;
    struct ext4_dir_entry dir;
    uint64_t block_size = ext4_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192];

    /* deleted files ? */
    if (root_inode.i_links_count == 0)
        return 0;

    if (root_inode.i_mode & 0x8000) /* file, no dir entries more */
        return 0;

    if (ext4_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext4_file_size(root_inode) / block_size;
        if (ext4_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        if (root_inode.i_flags & 0x80000)
        {
            ret_check = ext4_read_extent_block(disk, partition_offset, superblock, i, root_inode, buf);
        }
        else
        {
            ret_check = ext4_read_file_block(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);
        }

        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading inode dir block.\n");
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            return 0;
        }

        position = 0;

        while (position < block_size)
        {
            strcpy(path, prefix);

            if (ext4_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
                return 0;

            if (ext4_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
            {
               fprintf_light_red(stderr, "Error reading child inode.\n");
               return -1;
            } 

            dir.name[dir.name_len] = 0;
            strcat(path, (char*) dir.name);
            
            if (strcmp((const char *) dir.name, ".") != 0 &&
                strcmp((const char *) dir.name, "..") != 0)
            {
                fprintf_yellow(stdout, "inode %"PRIu32" ", dir.inode);
                if (child_inode.i_mode & 0x4000)
                {
                    fprintf_light_blue(stdout, "%s\n", path);
                }
                else if (child_inode.i_mode & 0x8000)
                {
                    fprintf_yellow(stdout, "%s\n", path);
                }
                else
                {
                    fprintf_red(stdout, "Not directory or file: %s", path);
                    fprintf_light_red(stdout, " -- %s\n",
                       child_inode.i_mode & 0x1000 ? "FIFO" :
                       child_inode.i_mode & 0x2000 ? "Character Device" : 
                       child_inode.i_mode & 0x6000 ? "Block Device" :
                       child_inode.i_mode & 0xa000 ? "Symbolic Link" :
                       child_inode.i_mode & 0xc000 ? "Socket" :
                       "UNKNOWN");
                }
                ext4_list_tree(disk, partition_offset, superblock, child_inode,
                               strcat(path, "/")); /* recursive call */
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext4_list_root_fs(FILE* disk, int64_t partition_offset,
                      struct ext4_superblock superblock, char* prefix)
{
    struct ext4_inode root;
    if (ext4_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    fprintf_yellow(stdout, "inode 2 %s\n", prefix);

    if (ext4_list_tree(disk, partition_offset, superblock, root, prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int ext4_reconstruct_file_sectors(FILE* disk, int64_t partition_offset,
                                  struct ext4_superblock superblock, 
                                  struct ext4_inode inode, char* copy_path)
{
    uint64_t block_size = ext4_block_size(superblock),
             file_size = ext4_file_size(inode);
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;

    if (inode.i_mode & 0x4000) /* dir entry, not a file */
    {
        fprintf_light_red(stderr, "Refusing to reconstruct dir inode, dir != "
                                  "file.\n");
        return -1;
    }

    if (file_size == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = file_size / block_size;
        if (file_size % block_size != 0)
            num_blocks += 1;
    }

    fprintf(stderr, "    .sectors = { ");

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext4_read_file_block_sectors(disk, partition_offset, superblock, i,
                                                 inode, (uint32_t*) buf);
        
        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading file block.\n");
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            fprintf_light_red(stderr, "Premature ending of file blocks.\n");
            return -1;
        }
    }

    fprintf(stderr, " }\n");

   return 0;
}

int ext4_reconstruct_file(FILE* disk, int64_t partition_offset,
                          struct ext4_superblock superblock, 
                          struct ext4_inode inode, char* copy_path)
{
    FILE* copy;
    uint64_t block_size = ext4_block_size(superblock),
             file_size = ext4_file_size(inode);
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;

    if (!((inode.i_mode & 0x8000) == 0x8000))
    {
        fprintf_light_red(stderr, "Refusing to reconstruct non-regular file "
                                  "inode.\n");
        return -1;
    }

    if (file_size == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = file_size / block_size;
        if (file_size % block_size != 0)
            num_blocks += 1;
    }

    if ((copy = fopen(copy_path, "wb")) == NULL)
    {
        fprintf_light_red(stderr, "Error opening copy file for writing.\n");
        return -1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        if (inode.i_flags & 0x80000) /* check if extents in use */
            ret_check = ext4_read_extent_block(disk, partition_offset,
                                               superblock, i, inode, buf);
        else
            ret_check = ext4_read_file_block(disk, partition_offset,
                                             superblock, i, inode,
                                             (uint32_t*) buf);

        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading file block.\n");
            fclose(copy);
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            fprintf_light_red(stderr, "Premature ending of file blocks.\n");
            fclose(copy);
            return -1;
        }

        if (file_size >= block_size)
        {
            if (fwrite(buf, sizeof(uint8_t), block_size, copy) != block_size)
            {
                fprintf_light_red(stderr, "Error could not write expected "
                                          "number of bytes to copy file.\n");
                return -1;
            }
            file_size -= block_size;
        }
        else
        {
            if (fwrite(buf, sizeof(uint8_t), file_size, copy) != file_size)
            {
                fprintf_light_red(stderr, "Error could not write expected"
                                          "number of bytes to copy file.\n");
                return -1;
            }
            break;
        }

    }

    fclose(copy);

   return 0;
}

/* recursive function listing a tree rooted at some directory.
 * recursion ends at leaf files.
 * depth-first
 */
int ext4_reconstruct_tree(FILE* disk, int64_t partition_offset, 
                          struct ext4_superblock superblock,
                          struct ext4_inode root_inode,
                          char* prefix,
                          char* copy_prefix)
{
    struct ext4_inode child_inode;
    struct ext4_dir_entry dir;
    uint64_t block_size = ext4_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192], copy[8192];

    if ((root_inode.i_mode & 0xa000) == 0xa000) /* symlink */
    {
        memcpy(buf, (uint8_t*) root_inode.i_block, 60);

        /* symlinks */
        if (ext4_file_size(root_inode) >= 60)
        {
            fprintf_light_red(stdout, "SYMLINK with target name >= "
                                      "60 bytes.\n");
            if (ext4_file_size(root_inode) >= 4096)
            {
                fprintf_light_red(stdout, "SYMLINK with target name >= 4096 "
                                          "bytes.\n");
                return -1;
            }

            ext4_read_extent_block(disk, partition_offset, superblock, 0,
                                   root_inode, buf);
        }
        strcpy(copy, copy_prefix);
        prefix[strlen(prefix)-1] = '\0'; /* remove trailing slash */
        strcat(copy, prefix);

        buf[ext4_file_size(root_inode)] = 0;
        memcpy(path, (char*) buf, strlen((char*) buf) + 1);

        fprintf_light_red(stdout, "Creating symlink %s -> %s\n", copy, path);
        symlink(path, copy);
        return 0;
    }
    else if ((root_inode.i_mode & 0x8000) == 0x8000) /* file, no dir entries more */
    {
        strcpy(copy, copy_prefix);
        prefix[strlen(prefix)-1] = '\0'; /* remove trailing slash */
        strcat(copy, prefix);
        fprintf_light_red(stdout, "Creating file: %s\n", copy);
        ext4_reconstruct_file(disk, partition_offset, superblock, root_inode,
                              copy);
        return 0;
    }
    else if ((root_inode.i_mode & 0x4000) == 0x4000)
    {
        strcpy(copy, copy_prefix);
        strcat(copy, prefix);
        fprintf_light_red(stdout, "Creating dir: %s\n", copy);
        mkdir(copy, ext4_inode_mode(root_inode.i_mode));
    }
    else
    {
        fprintf_light_red(stderr, "UNHANDLED Reconstruction File Type[%0.8"
                                  PRIx32"]: %s\n", root_inode.i_mode & 0x0f000,
                                  prefix);
    }

    if (ext4_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext4_file_size(root_inode) / block_size;
        if (ext4_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        if (root_inode.i_flags & 0x80000)
            ret_check = ext4_read_extent_block(disk, partition_offset, superblock, i, root_inode, buf);
        else
            ret_check = ext4_read_file_block(disk, partition_offset, superblock, i, root_inode, (uint32_t *) buf);
        
        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading inode dir block.\n");
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            fprintf_light_red(stderr, "Premature ending of inode dir "
                                      "blocks.\n");
            return 0;
        }

        position = 0;

        while (position < block_size)
        {
            strcpy(path, prefix);

            if (ext4_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
            {
                fprintf_light_red(stderr, "Encountered 0 inode, assuming "
                                          "unused dentry [%s].\n",
                                          prefix);
                if (dir.rec_len)
                {
                    position += dir.rec_len; /* deletions TODO wolf... */
                    continue;
                }
                else
                {
                    fprintf_light_red(stderr, "Unprocessed bytes ["PRIu64"] "
                                              "in dentry.\n",
                                              block_size - position);
                    return 0; /* error ? */
                }
            }

            if (ext4_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
            {
               fprintf_light_red(stderr, "Error reading child inode.\n");
               return -1;
            } 

            dir.name[dir.name_len] = 0;
            strcat(path, (char*) dir.name);

            if ((child_inode.i_mode & 0x4000) == 0x4000)
                fprintf_light_yellow(stdout, "Recursing on %s\n", dir.name);
            else if ((child_inode.i_mode & 0x8000) == 0x8000)
                fprintf_yellow(stdout, "Recursing on %s\n", dir.name);
            else
                fprintf_light_white(stdout, "Recursing on %s\n", dir.name);
            
            if (strcmp((const char *) dir.name, ".") != 0 &&
                strcmp((const char *) dir.name, "..") != 0)
            {
                if (child_inode.i_mode & 0x4000)
                {
                    fprintf_light_yellow(stdout, "%s\n", path);
                }
                else if (child_inode.i_mode & 0x8000)
                {
                    fprintf_yellow(stdout, "%s\n", path);
                }
                else
                {
                    fprintf_red(stdout, "%s\n", path);
                }
                ext4_reconstruct_tree(disk, partition_offset, superblock,
                                      child_inode, strcat(path, "/"),
                                      copy_prefix); /* recursive call */
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext4_reconstruct_root_fs(FILE* disk, int64_t partition_offset,
                             struct ext4_superblock superblock, char* prefix,
                             char* copy_prefix)
{
    struct ext4_inode root;
    if (ext4_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    if (ext4_reconstruct_tree(disk, partition_offset, superblock, root,
                              prefix, copy_prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int ext4_print_file_sectors(FILE* disk, int64_t partition_offset,
                            struct ext4_superblock superblock, 
                            struct ext4_inode inode, char* copy_path)
{
    FILE* copy;
    uint64_t block_size = ext4_block_size(superblock),
             file_size = ext4_file_size(inode);
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;

    if (inode.i_mode & 0x4000) /* dir entry, not a file */
    {
        fprintf_light_red(stderr, "Refusing to reconstruct dir inode, dir != "
                                  "file.\n");
        return -1;
    }

    if (file_size == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = file_size / block_size;
        if (file_size % block_size != 0)
            num_blocks += 1;
    }

    if ((copy = fopen(copy_path, "wb")) == NULL)
    {
        fprintf_light_red(stderr, "Error opening copy file for writing.\n");
        return -1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext4_read_file_block(disk, partition_offset, superblock, i,
                                         inode, (uint32_t*) buf);
        
        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading file block.\n");
            fclose(copy);
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            fprintf_light_red(stderr, "Premature ending of file blocks.\n");
            fclose(copy);
            return -1;
        }


        if (file_size >= block_size)
        {
            if (fwrite(buf, sizeof(uint8_t), block_size, copy) != block_size)
            {
                fprintf_light_red(stderr, "Error could not write expected "
                                          "number of bytes to copy file.\n");
                return -1;
            }
            file_size -= block_size;
        }
        else
        {
            if (fwrite(buf, sizeof(uint8_t), file_size, copy) != file_size)
            {
                fprintf_light_red(stderr, "Error could not write expected"
                                          "number of bytes to copy file.\n");
                return -1;
            }
            break;
        }

    }

    fclose(copy);

   return 0;
}

/* recursive function listing a tree rooted at some directory.
 * recursion ends at leaf files.
 * depth-first
 */
int ext4_print_tree_sectors(FILE* disk, int64_t partition_offset, 
                            struct ext4_superblock superblock,
                            struct ext4_inode root_inode,
                            char* prefix,
                            char* copy_prefix)
{
    struct ext4_inode child_inode;
    struct ext4_dir_entry dir;
    uint64_t block_size = ext4_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192], copy[8192];

    if (root_inode.i_mode & 0x8000) /* file, no dir entries more */
    {
        ext4_reconstruct_file_sectors(disk, partition_offset, superblock, root_inode,
                                      copy);
        return 0;
    }
    else if (root_inode.i_mode & 0x4000)
    {
    }

    if (ext4_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext4_file_size(root_inode) / block_size;
        if (ext4_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext4_read_file_block_sectors(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);
        
        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading inode dir block.\n");
            return -1;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            return 0;
        }

        position = 0;

        while (position < block_size)
        {
            strcpy(path, prefix);

            if (ext4_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
                return 0;

            if (ext4_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
            {
               fprintf_light_red(stderr, "Error reading child inode.\n");
               return -1;
            } 

            dir.name[dir.name_len] = 0;
            strcat(path, (char*) dir.name);
            
            if (strcmp((const char *) dir.name, ".") != 0 &&
                strcmp((const char *) dir.name, "..") != 0)
            {
                fprintf(stderr, "struct file_sector_map %s = {\n ", path);
                if (child_inode.i_mode & 0x4000)
                {
                    //fprintf_light_blue(stdout, "inode %"PRIu32" dir %s\n", dir.inode, path);
                    fprintf_light_blue(stderr, "    .path = \"%s\",\n", path);
                }
                else if (child_inode.i_mode & 0x8000)
                {
                    fprintf_light_yellow(stderr, "    .path = \"%s\",\n", path);
                }
                else
                {
                    fprintf_red(stderr, "%s\n", path);
                }
                ext4_print_tree_sectors(disk, partition_offset, superblock,
                                      child_inode, strcat(path, "/"), copy_prefix); /* recursive call */
                fprintf_yellow(stderr, "};\n");
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext4_print_root_fs_sectors(FILE* disk, int64_t partition_offset,
                               struct ext4_superblock superblock, char* prefix,
                               char* copy_prefix)
{
    struct ext4_inode root;
    if (ext4_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    fprintf_light_blue(stdout, "inode %"PRIu32" dir %s\n", (uint32_t) 2, prefix);

    if (ext4_print_tree_sectors(disk, partition_offset, superblock, root,
                                prefix, copy_prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int ext4_print_inode_mode(uint16_t i_mode)
{
    fprintf_yellow(stdout, "\t(  ");

    /* file format */
    if ((i_mode & 0xc000) == 0xc000)
        fprintf_blue(stdout, "EXT4_S_IFSOCK | ");
    if ((i_mode & 0xa000) == 0xa000)
        fprintf_blue(stdout, "EXT4_S_IFLNK | ");
    if (i_mode & 0x8000)
        fprintf_blue(stdout, "EXT4_S_IFREG | ");
    if ((i_mode & 0x6000) == 0x6000)
        fprintf_blue(stdout, "EXT4_S_IFBLK | ");
    if (i_mode & 0x4000)
        fprintf_blue(stdout, "EXT4_S_IFDIR | ");
    if (i_mode & 0x2000)
        fprintf_blue(stdout, "EXT4_S_IFCHR | ");
    if (i_mode & 0x1000)
        fprintf_blue(stdout, "EXT4_S_IFIFO | ");

    /* process execution/group override */
    if (i_mode & 0x0800)
        fprintf_blue(stdout, "EXT4_S_ISUID | ");
    if (i_mode & 0x0400)
        fprintf_blue(stdout, "EXT4_S_ISGID | ");
    if (i_mode & 0x0200)
        fprintf_blue(stdout, "EXT4_S_ISVTX | ");

    /* access control */
    if (i_mode & 0x0100)
        fprintf_blue(stdout, "EXT4_S_IRUSR | ");
    if (i_mode & 0x0080)
        fprintf_blue(stdout, "EXT4_S_IWUSR | ");
    if (i_mode & 0x0040)
        fprintf_blue(stdout, "EXT4_S_IXUSR | ");
    if (i_mode & 0x0020)
        fprintf_blue(stdout, "EXT4_S_IRGRP | ");
    if (i_mode & 0x0010)
        fprintf_blue(stdout, "EXT4_S_IWGRP | ");
    if (i_mode & 0x0008)
        fprintf_blue(stdout, "EXT4_S_IXGRP | ");
    if (i_mode & 0x0004)
        fprintf_blue(stdout, "EXT4_S_IROTH | ");
    if (i_mode & 0x0002)
        fprintf_blue(stdout, "EXT4_S_IWOTH | ");
    if (i_mode & 0x0001)
        fprintf_blue(stdout, "EXT4_S_IXOTH | ");


    fprintf_yellow(stdout, "\b\b )\n");
    return 0;
}

int ext4_print_inode_flags(uint16_t i_flags)
{
    fprintf_yellow(stdout, "\t(  ");
    if (i_flags & 0x1)
        fprintf_blue(stdout, "EXT4_SECRM_FL | ");
    if (i_flags & 0x2)
        fprintf_blue(stdout, "EXT4_UNRM_FL | ");    
    if (i_flags & 0x4)
        fprintf_blue(stdout, "EXT4_COMPR_FL | ");
    if (i_flags & 0x8)
        fprintf_blue(stdout, "EXT4_SYNC_FL | ");

    /* compression */
    if (i_flags & 0x10)
        fprintf_blue(stdout, "EXT4_IMMUTABLE_FL | ");
    if (i_flags & 0x20)
        fprintf_blue(stdout, "EXT4_APPEND_FL | ");
    if (i_flags & 0x40)
        fprintf_blue(stdout, "EXT4_NODUMP_FL | ");
    if (i_flags & 0x80)
        fprintf_blue(stdout, "EXT4_NOATIME_FL | ");

    if (i_flags & 0x100)
        fprintf_blue(stdout, "EXT4_DIRTY_FL | ");
    if (i_flags & 0x200)
        fprintf_blue(stdout, "EXT4_COMPRBLK_FL | ");
    if (i_flags & 0x400)
        fprintf_blue(stdout, "EXT4_NOCOMPR_FL | ");
    if (i_flags & 0x800)
        fprintf_blue(stdout, "EXT4_ECOMPR_FL | ");

    if (i_flags & 0x1000)
        fprintf_blue(stdout, "EXT4_BTREE_FL | ");
    if (i_flags & 0x2000)
        fprintf_blue(stdout, "EXT4_INDEX_FL | ");
    if (i_flags & 0x4000)
        fprintf_blue(stdout, "EXT4_IMAGIC_FL | ");
    if (i_flags & 0x8000)
        fprintf_blue(stdout, "EXT3_JOURNAL_DATA_FL | ");

    if (i_flags & 0x80000000)
        fprintf_blue(stdout, "EXT4_RESERVED_FL | ");

   fprintf_yellow(stdout, "\b\b )\n");
   return 0;
}

int print_ext4_inode_osd2(uint8_t osd2[12])
{
    fprintf_yellow(stdout, "i_osd2 --\\/\n");
    fprintf_yellow(stdout, "\tl_i_frag: %"PRIu8"\n", osd2[0]);
    fprintf_yellow(stdout, "\tl_i_fsize: %"PRIu8"\n", osd2[1]);
    /* osd2[2-3] are reserved on Linux */
    fprintf_yellow(stdout, "\tl_i_uid_high: %"PRIu16"\n", (uint16_t) osd2[4]);
    fprintf_yellow(stdout, "\tl_i_gid_high: %"PRIu16"\n", (uint16_t) osd2[6]);
    /* osd2[8-11] are reserved on Linux */
    return 0;
}

int ext4_print_inode_permissions(uint16_t i_mode)
{
    fprintf_yellow(stdout, "\tPermissions: 0%"PRIo16"\n", i_mode &
                                             (0x01c0 | 0x0038 | 0x007));
    return 0;
}

int ext4_print_inode(struct ext4_inode inode)
{
    int ret = 0;
    fprintf_yellow(stdout, "i_mode: 0x%"PRIx16"\n",
                           inode.i_mode);
    ext4_print_inode_mode(inode.i_mode);
    ext4_print_inode_permissions(inode.i_mode);
    if (inode.i_mode & 0x4000)
        ret = inode.i_block[0];
    fprintf_yellow(stdout, "i_uid: %"PRIu16"\n",
                           inode.i_uid);
    fprintf_yellow(stdout, "i_size: %"PRIu32"\n",
                           inode.i_size_lo);
    fprintf_yellow(stdout, "i_atime: %"PRIu32"\n",
                           inode.i_atime);
    fprintf_yellow(stdout, "i_ctime: %"PRIu32"\n",
                           inode.i_ctime);
    fprintf_yellow(stdout, "i_mtime: %"PRIu32"\n",
                           inode.i_mtime);
    fprintf_yellow(stdout, "i_dtime: %"PRIu32"\n",
                           inode.i_dtime);
    fprintf_yellow(stdout, "i_gid: %"PRIu16"\n",
                           inode.i_gid);
    fprintf_yellow(stdout, "i_links_count: %"PRIu16"\n",
                           inode.i_links_count);
    fprintf_yellow(stdout, "i_blocks: %"PRIu32"\n",
                           inode.i_blocks_lo);
    fprintf_yellow(stdout, "i_flags: %"PRIu32"\n",
                           inode.i_flags);
    ext4_print_inode_flags(inode.i_flags);
    fprintf_yellow(stdout, "i_osd1: %"PRIu32"\n",
                           inode.i_osd1);
    fprintf_yellow(stdout, "i_block[0]; direct: %"PRIu32"\n",
                           inode.i_block[0]); /* uint32_t i_block[15]; */
    fprintf_yellow(stdout, "i_block[1]; direct: %"PRIu32"\n",
                           inode.i_block[1]);
    fprintf_yellow(stdout, "i_block[2]; direct: %"PRIu32"\n",
                           inode.i_block[2]);
    fprintf_yellow(stdout, "i_block[3]; direct: %"PRIu32"\n",
                           inode.i_block[3]);
    fprintf_yellow(stdout, "i_block[4]; direct: %"PRIu32"\n",
                           inode.i_block[4]);
    fprintf_yellow(stdout, "i_block[5]; direct: %"PRIu32"\n",
                           inode.i_block[5]);
    fprintf_yellow(stdout, "i_block[6]; direct: %"PRIu32"\n",
                           inode.i_block[6]);
    fprintf_yellow(stdout, "i_block[7]; direct: %"PRIu32"\n",
                           inode.i_block[7]);
    fprintf_yellow(stdout, "i_block[8]; direct: %"PRIu32"\n",
                           inode.i_block[8]);
    fprintf_yellow(stdout, "i_block[9]; direct: %"PRIu32"\n",
                           inode.i_block[9]);
    fprintf_yellow(stdout, "i_block[10]; direct: %"PRIu32"\n",
                           inode.i_block[10]);
    fprintf_yellow(stdout, "i_block[11]; direct: %"PRIu32"\n",
                           inode.i_block[11]);
    fprintf_yellow(stdout, "i_block[12]; indirect: %"PRIu32"\n",
                           inode.i_block[12]);
    fprintf_yellow(stdout, "i_block[13]; doubly-indirect: %"PRIu32"\n",
                           inode.i_block[13]);
    fprintf_yellow(stdout, "i_block[14]; triply-indirect: %"PRIu32"\n",
                           inode.i_block[14]);
    fprintf_yellow(stdout, "i_generation: %"PRIu32"\n",
                           inode.i_generation);
    fprintf_yellow(stdout, "i_file_acl_lo: 0%.3"PRIo32"\n",
                           inode.i_file_acl_lo);
    fprintf_yellow(stdout, "i_faddr: %"PRIu32"\n",
                           inode.i_obso_faddr);
    print_ext4_inode_osd2(inode.i_osd2);
    return ret;
}


int print_ext4_block_group_descriptor(struct ext4_block_group_descriptor bgd)
{
    fprintf_light_cyan(stdout, "--- Analyzing Block Group Descriptor ---\n");
    fprintf_yellow(stdout, "bg_block_bitmap: %"PRIu64"\n",
                           ext4_bgd_block_bitmap(bgd));
    fprintf_yellow(stdout, "bg_inode_bitmap: %"PRIu64"\n",
                           ext4_bgd_inode_bitmap(bgd));
    fprintf_yellow(stdout, "bg_inode_table: %"PRIu64"\n",
                           ext4_bgd_inode_table(bgd));
    fprintf_yellow(stdout, "bg_free_blocks_count: %"PRIu32"\n",
                           ext4_bgd_free_blocks_count(bgd));
    fprintf_yellow(stdout, "bg_free_inodes_count: %"PRIu16"\n",
                           ext4_bgd_free_inodes_count(bgd));
    fprintf_yellow(stdout, "bg_used_dirs_count: %"PRIu16"\n",
                           ext4_bgd_used_dirs_count(bgd));
    /* uint16_t bg_pad; */
    /* uint8_t bg_reserved[12]; */
    return 0;
}

int print_ext4_superblock(struct ext4_superblock superblock)
{
    fprintf_yellow(stdout, "s_inodes_count: %"PRIu32"\n",
                           superblock.s_inodes_count);
    fprintf_yellow(stdout, "s_blocks_count: %"PRIu32"\n",
                           ext4_s_blocks_count(superblock));
    fprintf_yellow(stdout, "s_r_blocks_count: %"PRIu32"\n",
                           ext4_s_r_blocks_count(superblock));
    fprintf_yellow(stdout, "s_free_blocks_count: %"PRIu32"\n",
                           ext4_s_free_blocks_count(superblock));
    fprintf_yellow(stdout, "s_free_inodes_count: %"PRIu32"\n",
                           superblock.s_free_inodes_count);
    fprintf_yellow(stdout, "s_first_data_block: %"PRIu32"\n",
                           superblock.s_first_data_block);
    fprintf_yellow(stdout, "s_log_block_size: %"PRIu32"\n",
                           superblock.s_log_block_size);
    fprintf_yellow(stdout, "s_log_frag_size: %"PRIu32"\n",
                           superblock.s_log_cluster_size);
    fprintf_yellow(stdout, "s_blocks_per_group: %"PRIu32"\n",
                           superblock.s_blocks_per_group);
    fprintf_yellow(stdout, "s_frags_per_group: %"PRIu32"\n",
                           superblock.s_clusters_per_group);
    fprintf_yellow(stdout, "s_inodes_per_group: %"PRIu32"\n",
                           superblock.s_inodes_per_group);
    fprintf_yellow(stdout, "s_mtime: %"PRIu32"\n",
                           superblock.s_mtime);
    fprintf_yellow(stdout, "s_wtime: %"PRIu32"\n",
                           superblock.s_wtime);
    fprintf_yellow(stdout, "s_mnt_count: %"PRIu16"\n",
                           superblock.s_mnt_count);
    fprintf_yellow(stdout, "s_max_mnt_count: %"PRIu16"\n",
                           superblock.s_max_mnt_count);
    fprintf_yellow(stdout, "s_magic: %"PRIx16"\n",
                           superblock.s_magic);
    if (superblock.s_magic == 0xf30a)
    {
        fprintf_light_green(stdout, "Magic value matches EXT_SUPER_MAGIC\n"); 
    }
    else
    {
        fprintf_light_red(stdout, "Magic value does not match EXT_SUPER_MAGIC\n");
    }
    fprintf_yellow(stdout, "s_state: %"PRIu16"\n",
                           superblock.s_state);
    fprintf_light_yellow(stdout, "File System State: %s\n",
                                 ext4_s_state_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_errors: %"PRIu16"\n",
                           superblock.s_errors);
    fprintf_light_yellow(stdout, "Error State: %s\n",
                                 ext4_s_errors_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_minor_rev_level: %"PRIu16"\n",
                           superblock.s_minor_rev_level);
    fprintf_yellow(stdout, "s_lastcheck: %"PRIu32"\n",
                           superblock.s_lastcheck);
    fprintf_yellow(stdout, "s_checkinterval: %"PRIu32"\n",
                           superblock.s_checkinterval);
    fprintf_yellow(stdout, "s_creator_os: %"PRIu32"\n",
                           superblock.s_creator_os);
    fprintf_light_yellow(stdout, "Resolved OS: %s\n",
                                 ext4_s_creator_os_LUT[superblock.s_creator_os]);
    fprintf_yellow(stdout, "s_rev_level: %"PRIu32"\n",
                           superblock.s_rev_level);
    fprintf_light_yellow(stdout, "Revision Level: %s\n",
                                 ext4_s_rev_level_LUT[superblock.s_rev_level]);
    fprintf_yellow(stdout, "s_def_resuid: %"PRIu16"\n",
                           superblock.s_def_resuid);
    fprintf_yellow(stdout, "s_def_resgid: %"PRIu16"\n",
                           superblock.s_def_resgid);
    fprintf_yellow(stdout, "s_first_ino: %"PRIu32"\n",
                           superblock.s_first_ino);
    fprintf_yellow(stdout, "s_inode_size: %"PRIu16"\n",
                           superblock.s_inode_size);
    fprintf_yellow(stdout, "s_block_group_nr: %"PRIu16"\n",
                           superblock.s_block_group_nr);
    fprintf_yellow(stdout, "s_feature_compat: %"PRIu32"\n",
                           superblock.s_feature_compat);
    fprintf_yellow(stdout, "s_feature_incompat: %"PRIu32"\n",
                           superblock.s_feature_incompat);
    fprintf_yellow(stdout, "s_feature_ro_compat: %"PRIu32"\n",
                           superblock.s_feature_ro_compat);
    //uint8_t s_uuid[16];
    //uint8_t s_volume_name[16];
    //uint8_t s_last_mounted[64];
    fprintf_yellow(stdout, "s_algo_bitmap: %"PRIu32"\n",
                           superblock.s_algorithm_usage_bitmap);
    fprintf_yellow(stdout, "s_prealloc_blocks: %"PRIu8"\n",
    superblock.s_prealloc_blocks);                       
    fprintf_yellow(stdout, "s_prealloc_blocks: %"PRIu8"\n",
                           superblock.s_prealloc_blocks);
    //uint8_t alignment[2];
    //uint8_t s_journal_uuid[16];
    fprintf_yellow(stdout, "s_journal_inum: %"PRIu32"\n",
                           superblock.s_journal_inum);
    fprintf_yellow(stdout, "s_journal_dev: %"PRIu32"\n",
                           superblock.s_journal_dev);
    fprintf_yellow(stdout, "s_last_orphan: %"PRIu32"\n",
                           superblock.s_last_orphan);
    //uint32_t s_hash_seed[4];
    fprintf_yellow(stdout, "s_def_hash_version: %"PRIu8"\n",
                           superblock.s_def_hash_version);  
    //uint8_t padding[3];
    fprintf_yellow(stdout, "s_default_mount_options: %"PRIu32"\n",
                           superblock.s_default_mount_opts);
    fprintf_yellow(stdout, "s_first_meta_bg: %"PRIu32"\n",
                           superblock.s_first_meta_bg);
    return 0;
}

int ext4_probe(FILE* disk, int64_t partition_offset, struct ext4_superblock* superblock)
{
    if (partition_offset == 0)
    {
        fprintf_light_red(stderr, "ext4 probe failed on partition at offset: "
                                  "0x%.16"PRIx64".\n", partition_offset);
        return -1;
    }

    partition_offset += EXT4_SUPERBLOCK_OFFSET;

    if (fseeko(disk, partition_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%.16"PRIx64".\n",
                                  partition_offset);
        return -1;
    }

    if (fread(superblock, 1, sizeof(struct ext4_superblock), disk) !=
        sizeof(struct ext4_superblock))
    {
        fprintf_light_red(stderr, 
                          "Error while trying to read ext4 superblock.\n");
        return -1;
    }

    if (superblock->s_magic != 0xef53 || !(superblock->s_feature_ro_compat &
                                           EXT3_FEATURE_RO_COMPAT_UNSUPPORTED)
                                      ||
                                         !(superblock->s_feature_incompat &
                                           EXT3_FEATURE_INCOMPAT_UNSUPPORTED))
    {
        fprintf_light_red(stderr, "ext4 superblock s_magic[0x%0.4"PRIx16
                                  "] mismatch.\n", superblock->s_magic);
        return -1;
    }

    return 0;
}

int ext4_list_block_groups(FILE* disk, int64_t partition_offset,
                           struct ext4_superblock superblock)
{
    struct ext4_block_group_descriptor bgd;

    while (ext4_next_block_group_descriptor(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_ext4_block_group_descriptor(bgd))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
       fprintf(stdout, "\n");
    }
    return 0;
}

int ext4_list_block_groups_sectors(FILE* disk, int64_t partition_offset,
                                   struct ext4_superblock superblock)
{
    struct ext4_block_group_descriptor bgd;

    while (ext4_next_block_group_descriptor_sectors(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_ext4_block_group_descriptor(bgd))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
    }
    return 0;
}

int print_sectors_ext4_block_group_descriptor(int64_t offset, struct ext4_block_group_descriptor bgd, struct ext4_superblock superblock)
{
    uint32_t block_size = ext4_block_size(superblock);
    fprintf_yellow(stdout, "bg_block_bitmap sector %"PRId64"\n",
                           (ext4_bgd_block_bitmap(bgd) * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_bitmap sector %"PRIu32"\n",
                           (ext4_bgd_inode_bitmap(bgd) * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_table sector start %"PRIu32"\n",
                           (ext4_bgd_inode_table(bgd) * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_table sector end %"PRIu32"\n",
                            (ext4_bgd_inode_table(bgd) * block_size + offset + superblock.s_inodes_per_group * sizeof(struct ext4_inode)) / SECTOR_SIZE);
    fprintf_yellow(stdout, "BGD end sector %"PRId64"\n",
                           (ext4_bgd_block_bitmap(bgd) * block_size + offset + superblock.s_blocks_per_group * block_size) / SECTOR_SIZE);
    return 0;
}

int ext4_serialize_bgd_sectors(struct bson_info* serialized,
                               struct ext4_block_group_descriptor bgd,
                               struct ext4_superblock* superblock,
                               int64_t offset)
{
    uint64_t block_size = ext4_block_size(*superblock);
    uint64_t sector;
    struct bson_kv value;

    value.type = BSON_INT64;

    sector = (ext4_bgd_block_bitmap(bgd) * block_size + offset) / SECTOR_SIZE;
    value.key = "block_bitmap_sector_start";
    value.data = &sector; 

    bson_serialize(serialized, &value);

    sector = (ext4_bgd_block_bitmap(bgd) * block_size + offset + block_size) /
             SECTOR_SIZE - 1;
    value.key = "block_bitmap_sector_end";
    value.data = &sector; 

    bson_serialize(serialized, &value);

    sector = (ext4_bgd_inode_bitmap(bgd) * block_size + offset) / SECTOR_SIZE;
    value.key = "inode_bitmap_sector_start";
    value.data = &sector; 

    bson_serialize(serialized, &value);
    
    sector = (ext4_bgd_inode_bitmap(bgd) * block_size + offset + block_size) / 
             SECTOR_SIZE - 1;
    value.key = "inode_bitmap_sector_end";
    value.data = &sector; 

    bson_serialize(serialized, &value);
    
    sector = (ext4_bgd_inode_table(bgd) * block_size + offset) / SECTOR_SIZE;
    value.key = "inode_table_sector_start";
    value.data = &sector; 

    bson_serialize(serialized, &value);
    
    sector = (ext4_bgd_inode_table(bgd) * block_size + offset + 
              superblock->s_inodes_per_group * 
              sizeof(struct ext4_inode)) / SECTOR_SIZE - 1;
    value.key = "inode_table_sector_end";
    value.data = &sector; 

    bson_serialize(serialized, &value);
    
    return EXIT_SUCCESS;
}

int ext4_print_sectormap(FILE* disk, int64_t partition_offset,
                         struct ext4_superblock superblock)
{
    /* print superblock sector */
    fprintf_yellow(stdout, "Superblock sector %"PRId64"\n", (partition_offset + EXT4_SUPERBLOCK_OFFSET) / SECTOR_SIZE);

    /* walk block group descriptor table */
    struct ext4_block_group_descriptor bgd;

    while (ext4_next_block_group_descriptor(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_sectors_ext4_block_group_descriptor(partition_offset, bgd, superblock))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
    }

    /* walk inode table */
    ext4_print_root_fs_sectors(disk, partition_offset, superblock, "/", ""); 
    return 0;
}

char* ext4_last_mount_point(struct ext4_superblock* superblock)
{
    return (char *) (superblock->s_last_mounted);
}

int ext4_serialize_fs(struct ext4_superblock* superblock,
                      char* mount_point, 
                      FILE* serializedf)
{
    int32_t fs_type = MBR_FS_TYPE_EXT4;
    /* round up integer arithmetic */
    int32_t num_block_groups = (ext4_s_blocks_count(*superblock) +
                                (superblock->s_blocks_per_group - 1)) /
                                superblock->s_blocks_per_group;
    /* plus 2 because need to rebase on fist usable inode; also
     * the '/' root inode is inside the reserved inodes---always inode 2 */
    int32_t num_files = superblock->s_inodes_count -
                        superblock->s_free_inodes_count -
                        superblock->s_first_ino + 2;
    struct bson_info* serialized;
    struct bson_info* sectors;
    struct bson_kv value;

    serialized = bson_init();
    sectors = bson_init();

    value.type = BSON_INT32;
    value.key = "fs_type";
    value.data = &(fs_type);

    bson_serialize(serialized, &value);

    value.type = BSON_STRING;
    value.key = "mount_point";
    value.size = strlen(mount_point);
    value.data = mount_point;

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "num_block_groups";
    value.data = &(num_block_groups);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "num_files";
    value.data = &(num_files);

    bson_serialize(serialized, &value);

    value.key = "superblock";
    value.type = BSON_BINARY;
    value.size = sizeof(struct ext4_superblock);
    value.subtype = BSON_BINARY_GENERIC;
    value.data = superblock;

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    bson_writef(serialized, serializedf);
    bson_cleanup(sectors);
    bson_cleanup(serialized);

    return EXIT_SUCCESS;
}

int ext4_serialize_bgds(FILE* disk, int64_t partition_offset,
                        struct ext4_superblock* superblock, FILE* serializef)
{
    struct ext4_block_group_descriptor bgd;
    struct bson_info* serialized;
    struct bson_kv v_bgd, v_sector;
    uint32_t sector = 0;


    serialized = bson_init();
    
    v_bgd.type = BSON_BINARY;
    v_bgd.key = "bgd";
    v_bgd.subtype = BSON_BINARY_GENERIC;
    v_bgd.size = sizeof(struct ext4_block_group_descriptor);
    
    v_sector.type = BSON_INT32;
    v_sector.key = "sector";

    while ((sector = ext4_next_block_group_descriptor(disk,
                                                     partition_offset,
                                                     *superblock,
                                                     &bgd)) > 0)
    {
        v_bgd.data = &bgd;
        bson_serialize(serialized, &v_bgd);

        v_sector.data = &sector;
        bson_serialize(serialized, &v_sector);

        ext4_serialize_bgd_sectors(serialized, bgd, superblock,
                                   partition_offset);

        bson_finalize(serialized);
        bson_writef(serialized, serializef);

        bson_reset(serialized);
    }

    bson_cleanup(serialized);

    return EXIT_SUCCESS;
}

int ext4_serialize_file_extent_sectors(FILE* disk, int64_t partition_offset,
                                       struct ext4_superblock superblock,
                                       uint32_t block_num,
                                       struct ext4_inode inode,
                                       struct bson_info* sectors)
{
    int i;
    struct ext4_extent_header hdr; 
    struct ext4_extent_idx idx;
    struct ext4_extent_idx idx2; /* lookahead when searching for block_num */
    struct ext4_extent extent;
    uint8_t buf[ext4_block_size(superblock)];

    struct bson_kv value;
    int64_t sector;
    uint32_t sectors_per_block = ext4_block_size(superblock) / SECTOR_SIZE;
    char count[11];
    value.type = BSON_INT32;
    value.key = count;

    memcpy(buf, inode.i_block, (size_t) 60);
    hdr = *((struct ext4_extent_header*) buf);
    idx.ei_block = (uint32_t) 2 << 31;

    for (i = 0; i < hdr.eh_entries; i++)
    {
        if (hdr.eh_depth)
        {
            idx2 =  * ((struct ext4_extent_idx*)
                            &(buf[sizeof(struct ext4_extent_header) +
                                  sizeof(struct ext4_extent_idx)*i])); 
            if (hdr.eh_entries == 1)
            {
                ext4_read_block(disk, partition_offset, superblock,
                                ext4_extent_index_leaf(idx2), buf);
                i = -1; /* allow loop-expr to run (++) */
                hdr = *((struct ext4_extent_header*) buf);
                idx.ei_block = (uint32_t) 2 << 31;
                continue;
            }

            if ((block_num < idx2.ei_block &&
                block_num >= idx.ei_block))
            {
                ext4_read_block(disk, partition_offset, superblock,
                                ext4_extent_index_leaf(idx), buf);
                i = -1; /* allow loop-expr to run (++) */
                hdr = *((struct ext4_extent_header*) buf);
                idx.ei_block = (uint32_t) 2 << 31;
                continue;
            }
            idx = idx2;
        }
        else
        {
            extent = * ((struct ext4_extent*)
                            &(buf[sizeof(struct ext4_extent_header) +
                                  sizeof(struct ext4_extent)*i])); 
            if (extent.ee_block <= block_num &&
                block_num < extent.ee_block + extent.ee_len)
            {
                block_num -= extent.ee_block; /* rebase */
                sector = (ext4_extent_start(extent) + block_num);
                sector *= ext4_block_size(superblock);
                sector += partition_offset;
                sector /= SECTOR_SIZE;

                for (i = 0; i < sectors_per_block; i++)
                {
                    snprintf(count, 11, "%"PRIu32,
                                           ((block_num + extent.ee_block) * sectors_per_block) + i);
                    sector += i;
                    value.data = &sector;
                    bson_serialize(sectors, &value);
                }

                return 0;
            }
        }
    }

    return -1;
}

int ext4_serialize_file_block_sectors(FILE* disk, int64_t partition_offset,
                                 struct ext4_superblock superblock, uint32_t block_num,
                                 struct ext4_inode inode, struct bson_info* sectors)
{
    uint32_t block_size = ext4_block_size(superblock);
    uint32_t addresses_in_block = block_size / 4;
    uint32_t buf[addresses_in_block];
    uint32_t sectors_per_block = block_size / SECTOR_SIZE;
    uint32_t i;
    
    /* ranges for lookup */
    uint32_t direct_low = 0;
    uint32_t direct_high = 11;
    uint32_t indirect_low = direct_high + 1;
    uint32_t indirect_high = direct_high + (addresses_in_block);
    uint32_t double_low = indirect_high + 1;
    uint32_t double_high = indirect_high + (addresses_in_block)*
                                           (addresses_in_block);
    uint32_t triple_low = double_high + 1;
    uint32_t triple_high = double_high + (addresses_in_block)*
                                         (addresses_in_block)*
                                         (addresses_in_block);

    struct bson_kv value;
    char count[11];
    int64_t sector;
    value.type = BSON_INT32;
    value.key = count;

    if (block_num < direct_low || block_num > triple_high)
    {
        fprintf_light_red(stderr, "File block outside of range of inode.\n");
        return -1;
    }

    /* figure out type of block lookup (direct, indirect, double, treble) */
    /* DIRECT */
    if (block_num <= direct_high)
    {
        if (inode.i_block[block_num] == 0)
            return 1; /* finished */

        sector = (inode.i_block[block_num] * ext4_block_size(superblock) +
                  partition_offset) / SECTOR_SIZE;

        for (i = 0; i < sectors_per_block; i++)
        {
            snprintf(count, 11, "%"PRIu32, (block_num * sectors_per_block) + i);
            sector += i;
            value.data = &sector;
            bson_serialize(sectors, &value);
        }

        return 0;
    }

    /* INDIRECT */
    if (block_num <= indirect_high)
    {
        block_num -= indirect_low; /* rebase, 0 is beginning indirect block range */
        
        if (inode.i_block[12] == 0)
            return 1; /* finished */

        ext4_read_block(disk, partition_offset, superblock, inode.i_block[12],
                        (uint8_t*) buf);

        if (buf[block_num] == 0)
            return 1;

        sector = (buf[block_num] * ext4_block_size(superblock) +
                  partition_offset) / SECTOR_SIZE;

        for (i = 0; i < sectors_per_block; i++)
        {
            snprintf(count, 11, "%"PRIu32, ((block_num + indirect_low) *
                                             sectors_per_block) + i);
            sector += i;
            value.data = &sector;
            bson_serialize(sectors, &value);
        }

        return 0;
    }

    /* DOUBLE */
    if (block_num <= double_high)
    {
        block_num -= double_low;

        if (inode.i_block[13] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* double */
                        superblock, inode.i_block[13], (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        sector = (buf[block_num % addresses_in_block] *
                  ext4_block_size(superblock) + partition_offset) /
                  SECTOR_SIZE;

        for (i = 0; i < sectors_per_block; i++)
        {
            snprintf(count, 11, "%"PRIu32, ((block_num + double_low) *
                                           sectors_per_block) + i);
            sector += i;
            value.data = &sector;
            bson_serialize(sectors, &value);
        }

        return 0;
    }

    /* TRIPLE */
    if (block_num <= triple_high)
    {
        block_num -= triple_low;

        if (inode.i_block[14] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* triple */
                        superblock, inode.i_block[14], (uint8_t*) buf);

        if (buf[block_num / (addresses_in_block*addresses_in_block)] == 0)
            return 1;
        
        ext4_read_block(disk, partition_offset, /* double */
                        superblock,
                        buf[block_num / (addresses_in_block*
                                         addresses_in_block)],
                        (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext4_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        sector = (buf[block_num % addresses_in_block] *
                  ext4_block_size(superblock) + partition_offset) /
                  SECTOR_SIZE;

        for (i = 0; i < sectors_per_block; i++)
        {
            snprintf(count, 11, "%"PRIu32, ((block_num + triple_low) *
                                             sectors_per_block) + i);
            sector += i;
            value.data = &sector;
            bson_serialize(sectors, &value);
        }

        return 0;
    }

    return -1;
}

int ext4_serialize_file_sectors(FILE* disk, int64_t partition_offset,
                                struct ext4_superblock superblock, 
                                struct ext4_inode inode,
                                struct bson_info* serialized)
{
    uint64_t block_size = ext4_block_size(superblock),
             file_size = ext4_file_size(inode);
    struct bson_info* sectors;
    struct bson_kv value;
    uint64_t num_blocks;
    uint64_t count;

    int ret_check;

    if (file_size == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = file_size / block_size;
        if (file_size % block_size != 0)
            num_blocks += 1;
    }

    value.type = BSON_ARRAY;
    value.key = "sectors";
    
    sectors = bson_init();

    if ((inode.i_mode & 0xa000) == 0xa000)
        goto skip;

    /* go through each valid block of the inode */
    count = 0;
    while (num_blocks) 
    {
        if (inode.i_flags & 0x80000) /* check if extents in use */
            ret_check = ext4_serialize_file_extent_sectors(disk, partition_offset,
                                                          superblock, count, inode,
                                                          sectors);
        else
            ret_check = ext4_serialize_file_block_sectors(disk, partition_offset,
                                                          superblock, count, inode,
                                                          sectors);
        
        if (ret_check < 0) /* error reading */
        {
            count++;
            num_blocks--;
            continue;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            fprintf_light_red(stderr, "Premature ending of file blocks.\n");
            exit(1);
            return -1;
        }

        count++;
        num_blocks--;
    }

skip:

    bson_finalize(sectors);
    value.data = sectors;

    bson_serialize(serialized, &value);
    bson_cleanup(sectors);

   return 0;
}

int ext4_serialize_tree(FILE* disk, int64_t partition_offset, 
                        struct ext4_superblock superblock,
                        struct ext4_inode root_inode,
                        char* prefix,
                        FILE* serializef,
                        struct bson_info* bson)
{
    struct ext4_inode child_inode;
    struct ext4_dir_entry dir;
    uint64_t block_size = ext4_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192];

    struct bson_kv value;
    bool is_dir = (root_inode.i_mode & 0x4000) == 0x4000;
    
    if ((root_inode.i_mode & 0xa000) == 0xa000) /* symlink */
    {
        value.type = BSON_STRING;
        value.size = strlen(prefix);
        value.key = "path";
        value.data = prefix;

        bson_serialize(bson, &value);

        value.type = BSON_BOOLEAN;
        value.key = "is_dir";
        value.data = &is_dir;

        bson_serialize(bson, &value);

        value.type = BSON_BINARY;
        value.subtype = BSON_BINARY_GENERIC;
        value.size = sizeof(struct ext4_inode);
        value.key = "inode";
        value.data = &root_inode;

        bson_serialize(bson, &value);

        ext4_serialize_file_sectors(disk, partition_offset, superblock,
                                    root_inode, bson);

        bson_finalize(bson);
        bson_writef(bson, serializef);
        bson_cleanup(bson);
        return 0;
    }
    else if ((root_inode.i_mode & 0x8000) == 0x8000) /* file, no dir entries more */
    {
        value.type = BSON_STRING;
        value.size = strlen(prefix);
        value.key = "path";
        value.data = prefix;

        bson_serialize(bson, &value);

        value.type = BSON_BOOLEAN;
        value.key = "is_dir";
        value.data = &is_dir;

        bson_serialize(bson, &value);

        value.type = BSON_BINARY;
        value.subtype = BSON_BINARY_GENERIC;
        value.size = sizeof(struct ext4_inode);
        value.key = "inode";
        value.data = &root_inode;

        bson_serialize(bson, &value);

        ext4_serialize_file_sectors(disk, partition_offset, superblock,
                                    root_inode, bson);
        
        bson_finalize(bson);
        bson_writef(bson, serializef);
        bson_cleanup(bson);        
        return 0;
    }
    else if ((root_inode.i_mode & 0x4000) == 0x4000)
    {
        value.type = BSON_STRING;
        value.size = strlen(prefix);
        value.key = "path";
        value.data = prefix;

        bson_serialize(bson, &value);

        value.type = BSON_BOOLEAN;
        value.key = "is_dir";
        value.data = &is_dir;

        bson_serialize(bson, &value);

        value.type = BSON_BINARY;
        value.subtype = BSON_BINARY_GENERIC;
        value.size = sizeof(struct ext4_inode);
        value.key = "inode";
        value.data = &root_inode;

        bson_serialize(bson, &value);

        ext4_serialize_file_sectors(disk, partition_offset,
                                    superblock, root_inode, bson);
        
        bson_finalize(bson);
        bson_writef(bson, serializef);
        bson_cleanup(bson);
    }

    if (ext4_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext4_file_size(root_inode) / block_size;
        if (ext4_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        if (root_inode.i_flags & 0x80000)
            ret_check = ext4_read_extent_block(disk, partition_offset, superblock, i, root_inode, buf);
        else
            ret_check = ext4_read_file_block(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);

        if (ret_check < 0) /* error reading */
        {
            fprintf_light_red(stderr, "Error reading inode dir block. "
                                      "Assuming  hole.\n");
            continue;
        }
        else if (ret_check > 0) /* no more blocks? */
        {
            return 0;
        }

        position = 0;

        while (position < block_size)
        {
            strcpy(path, prefix);
            if (strlen(path) > 1)
                strcat(path, "/");

            if (ext4_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from "
                                          "block.\n");
                return -1;
            }

            if (dir.inode == 0)
            {
                position += dir.rec_len;
                continue;
            }

            bson = bson_init();

            if (ext4_read_inode_serialized(disk, partition_offset, superblock,
                                           dir.inode, &child_inode, bson))
            {
               fprintf_light_red(stderr, "Error reading child inode.\n");
               return -1;
            } 

            dir.name[dir.name_len] = 0;
            strcat(path, (char*) dir.name);
            
            if (strcmp((const char *) dir.name, ".") != 0 &&
                strcmp((const char *) dir.name, "..") != 0)
            {
                if (child_inode.i_mode & 0x4000)
                {
                }
                else if (child_inode.i_mode & 0x8000)
                {
                }
                else
                {
                    fprintf_red(stderr, "Not directory or file: %s\n", path);
                }
                ext4_serialize_tree(disk, partition_offset, superblock,
                                    child_inode, path, serializef,
                                    bson); /* recursive call */
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext4_serialize_fs_tree(FILE* disk, int64_t partition_offset,
                           struct ext4_superblock* superblock, char* mount,
                           FILE* serializef)
{
    struct ext4_inode root;
    struct bson_info* bson;
    char* buf = malloc(strlen(mount) + 1);

    if (buf == NULL)
    {
        fprintf_light_red(stderr, "Error allocating root dir path string.\n");
        return -1;
    }

    memcpy(buf, mount, strlen(mount));
    buf[strlen(mount) + 1] = '\0';

    bson = bson_init();

    if (ext4_read_inode_serialized(disk, partition_offset, *superblock, 2,\
                                   &root, bson))
    {
        free(buf);
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    if (ext4_serialize_tree(disk, partition_offset, *superblock, root,
                            buf, serializef, bson))
    {
        free(buf);
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    free(buf);

    return 0;
}
