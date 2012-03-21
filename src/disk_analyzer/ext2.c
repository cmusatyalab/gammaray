#define _FILE_OFFSET_BITS 64

#include "ext2.h"

#include <string.h>

#include <sys/stat.h> 
#include <sys/types.h>

struct ext2_dir_entry
{
    uint32_t inode;     /* 4 bytes */
    uint16_t rec_len;   /* 6 bytes */
    uint8_t name_len;   /* 7 bytes */
    uint8_t file_type;  /* 8 bytes */
    uint8_t name[255];  /* 263 bytes */
} __attribute__((packed));

char* s_creator_os_LUT[] = {
                                "EXT2_OS_LINUX","EXT2_OS_HURD","EXT2_OS_MASIX",
                                "EXT2_OS_FREEBSD","EXT2_OS_LITES"
                           };

char* s_rev_level_LUT[] = {
                                "EXT2_GOOD_OLD_REV","EXT2_DYNAMIC_REV"
                          };

char* s_state_LUT[] = {
                                "","EXT2_VALID_FS","EXT2_ERROR_FS"
                      };

char* s_errors_LUT[] = {
                                "","EXT2_ERRORS_CONTINUE","EXT2_ERRORS_RO",
                                "EXT2_ERRORS_PANIC"
                       };

int ascii_dump(uint8_t* buf, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if (buf[i] <= 31 || buf[i] >= 127)
            fprintf(stdout, ".");
        else
            fprintf(stdout, "%c", (char) buf[i]);
    }

    return 0;
}

int ext2_print_block(uint8_t* buf, uint32_t block_size)
{
    uint32_t i;

    for (i = 0; i < block_size; i++)
    {
        if (i % 16 == 0)
        {
            if (i > 0)
            {
                fprintf(stdout, " |");
                ascii_dump(&(buf[i-16]), 16);
                fprintf(stdout, "|\n");
            }
            fprintf(stdout, "%.8"PRIx32, i);
        }

        if (i % 8 == 0)
            fprintf(stdout, " %.2"PRIx8" ", buf[i]);
        else
            fprintf(stdout, "%.2"PRIx8" ", buf[i]);
    }

    if (i > 0)
    {
        fprintf(stdout, " |");
        if (block_size % 16)
            ascii_dump(&(buf[i-(block_size % 16)]), block_size % 16);
        else
            ascii_dump(&(buf[i-16]), 16);
        fprintf(stdout, "|\n");
    }
    
    return 0;
}

int ext2_print_superblock(struct ext2_superblock superblock)
{
    fprintf_yellow(stdout, "s_inodes_count: %"PRIu32"\n",
                           superblock.s_inodes_count);
    fprintf_yellow(stdout, "s_blocks_count: %"PRIu32"\n",
                           superblock.s_blocks_count);
    fprintf_yellow(stdout, "s_r_blocks_count: %"PRIu32"\n",
                           superblock.s_r_blocks_count);
    fprintf_yellow(stdout, "s_free_blocks_count: %"PRIu32"\n",
                           superblock.s_free_blocks_count);
    fprintf_yellow(stdout, "s_free_inodes_count: %"PRIu32"\n",
                           superblock.s_free_inodes_count);
    fprintf_yellow(stdout, "s_first_data_block: %"PRIu32"\n",
                           superblock.s_first_data_block);
    fprintf_yellow(stdout, "s_log_block_size: %"PRIu32"\n",
                           superblock.s_log_block_size);
    fprintf_yellow(stdout, "s_log_frag_size: %"PRIu32"\n",
                           superblock.s_log_frag_size);
    fprintf_yellow(stdout, "s_blocks_per_group: %"PRIu32"\n",
                           superblock.s_blocks_per_group);
    fprintf_yellow(stdout, "s_frags_per_group: %"PRIu32"\n",
                           superblock.s_frags_per_group);
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
        fprintf_light_green(stdout, "Magic value matches EXT_SUPER_MAGIC\n"); 
    }
    else
    {
        fprintf_light_red(stdout,
                          "Magic value does not match EXT_SUPER_MAGIC\n");
    }
    fprintf_yellow(stdout, "s_state: %"PRIu16"\n",
                           superblock.s_state);
    fprintf_light_yellow(stdout, "File System State: %s\n",
                                 s_state_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_errors: %"PRIu16"\n",
                           superblock.s_errors);
    fprintf_light_yellow(stdout, "Error State: %s\n",
                                 s_errors_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_minor_rev_level: %"PRIu16"\n",
                           superblock.s_minor_rev_level);
    fprintf_yellow(stdout, "s_lastcheck: %"PRIu32"\n",
                           superblock.s_lastcheck);
    fprintf_yellow(stdout, "s_checkinterval: %"PRIu32"\n",
                           superblock.s_checkinterval);
    fprintf_yellow(stdout, "s_creator_os: %"PRIu32"\n",
                           superblock.s_creator_os);
    fprintf_light_yellow(stdout, "Resolved OS: %s\n",
                                 s_creator_os_LUT[superblock.s_creator_os]);
    fprintf_yellow(stdout, "s_rev_level: %"PRIu32"\n",
                           superblock.s_rev_level);
    fprintf_light_yellow(stdout, "Revision Level: %s\n",
                                 s_rev_level_LUT[superblock.s_rev_level]);
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
                           superblock.s_algo_bitmap);
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
                           superblock.s_default_mount_options);
    fprintf_yellow(stdout, "s_first_meta_bg: %"PRIu32"\n",
                           superblock.s_first_meta_bg);
    return 0;
}

uint32_t ext2_block_size(struct ext2_superblock superblock)
{
    return ((uint32_t) 1024) << superblock.s_log_block_size;
}

uint32_t ext2_num_block_groups(struct ext2_superblock superblock)
{
    uint32_t blocks = superblock.s_blocks_count;
    uint32_t blocks_per_group = superblock.s_blocks_per_group;

    return (blocks + blocks_per_group - 1) / blocks_per_group;
}

int ext2_next_block_group_descriptor(FILE* disk,
                                     int64_t partition_offset,
                                     struct ext2_superblock superblock,
                                     struct ext2_block_group_descriptor* bgd)
{
    static uint32_t i = 0;
    uint64_t offset = (superblock.s_first_data_block+1) * ext2_block_size(superblock);
    uint32_t num_block_groups = ext2_num_block_groups(superblock);

    for (; i < num_block_groups;)
    {
        if (fseeko(disk, partition_offset + offset + i*sizeof(struct ext2_block_group_descriptor), 0))
        {
            fprintf_light_red(stderr, "error seeking to position 0x%lx.\n",
                              offset);
            return -1;
        }

        if (fread(bgd, 1, sizeof(struct ext2_block_group_descriptor), disk) !=
            sizeof(struct ext2_block_group_descriptor))
        {
            fprintf_light_red(stderr, 
                              "error while trying to read ext2 block group "
                              "descriptor.\n");
            return -1;
        }
        i++;
        return 1;
    }

    return 0; 
}

int ext2_next_block_group_descriptor_sectors(FILE* disk,
                                             int64_t partition_offset,
                                             struct ext2_superblock superblock,
                                             struct ext2_block_group_descriptor* bgd)
{
    static uint32_t i = 0;
    uint64_t offset = (superblock.s_first_data_block+1) * ext2_block_size(superblock);
    uint32_t num_block_groups = ext2_num_block_groups(superblock);

    for (; i < num_block_groups;)
    {
        if (fseeko(disk, partition_offset + offset + i*sizeof(struct ext2_block_group_descriptor), 0))
        {
            fprintf_light_red(stderr, "error seeking to position 0x%lx.\n",
                              offset);
            return -1;
        }

        if (fread(bgd, 1, sizeof(struct ext2_block_group_descriptor), disk) !=
            sizeof(struct ext2_block_group_descriptor))
        {
            fprintf_light_red(stderr, 
                              "Error while trying to read ext2 block group "
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

int write_block(FILE* dest, uint32_t total_size, uint32_t block_size,
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

int ext2_print_dir_entry(uint32_t entry, struct ext2_dir_entry dir)
{
    fprintf_yellow(stdout, "%d ext2_dir_entry.inode: %"PRIu32"\n", entry,
                           dir.inode);
    fprintf_yellow(stdout, "%d ext2_dir_entry.rec_len: %"PRIu16"\n", entry,
                           dir.rec_len);
    fprintf_yellow(stdout, "%d ext2_dir_entry.name_len: %"PRIu8"\n", entry,
                           dir.name_len);
    if (dir.name_len < 256)
        dir.name[dir.name_len] = '\0';
    else
        dir.name[0] = '\0';
    fprintf_yellow(stdout, "%d ext2_dir_entry.name: %s\n", entry, dir.name);
    fprintf(stdout, "\n\n");
    return 0;
} 

int ext2_print_dir_entries(uint8_t* bytes, uint32_t len)
{
    uint32_t i;
    uint32_t num_entries = len / sizeof(struct ext2_dir_entry);

    for (i = 0; i < num_entries; i++)
        ext2_print_dir_entry(i, *((struct ext2_dir_entry*)
                                  (bytes + i*sizeof(struct ext2_dir_entry))));
    return 0;
}


int read_dir_entry(uint32_t offset, FILE* disk, struct ext2_dir_entry* dir)
{
   if (fseeko(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
        return -1;
    }

    if (fread(dir, 1, sizeof(struct ext2_dir_entry), disk) != sizeof(struct ext2_dir_entry))
    {
        fprintf_light_red(stdout, "Error while trying to read ext2 dir"
                                  "entry.\n");
        return -1;
    }

    if (dir->name_len < 256)
        dir->name[dir->name_len] = '\0';
    else
        dir->name[0] = '\0';

    return dir->rec_len;
}

mode_t ext2_inode_mode(uint16_t i_mode)
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

uint64_t ext2_block_offset(uint64_t block_num, struct ext2_superblock superblock)
{
    uint64_t block_size = ext2_block_size(superblock);
    return block_size * block_num;
}

int ext2_read_block(FILE* disk, int64_t partition_offset, 
                    struct ext2_superblock superblock, uint64_t block_num, 
                    uint8_t* buf)
{
    uint64_t block_size = ext2_block_size(superblock);
    uint64_t offset = ext2_block_offset(block_num, superblock);
    offset += partition_offset;

    if (fseeko(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error while reading block seeking to position 0x%lx.\n", 
                                  offset);
        return -1;
    }

    if (fread(buf, 1, block_size, disk) != block_size)
    {
        fprintf_light_red(stdout, "Error while trying to read block.\n");
        return -1;
    }

    return 0;

}

int ext2_read_bgd(FILE* disk, int64_t partition_offset,
                 struct ext2_superblock superblock,
                 uint32_t block_group,
                 struct ext2_block_group_descriptor* bgd)
{
    uint64_t offset = (superblock.s_first_data_block+1) *
                      ext2_block_size(superblock) +
                      block_group*sizeof(struct ext2_block_group_descriptor);

    if (fseeko(disk, partition_offset + offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
        return -1;
    }

    if (fread(bgd, 1, sizeof(struct ext2_block_group_descriptor), disk) !=
        sizeof(struct ext2_block_group_descriptor))
    {
        fprintf_light_red(stderr, 
                          "Error while trying to read ext2 Block Group "
                          "Descriptor.\n");
        return -1;
    }

    return 0;
}

int ext2_read_inode(FILE* disk, int64_t partition_offset,
                    struct ext2_superblock superblock,
                    uint32_t inode_num, struct ext2_inode* inode)
{
    uint64_t block_group = (inode_num - 1) / superblock.s_inodes_per_group;
    struct ext2_block_group_descriptor bgd;
    uint64_t inode_table_offset;
    uint64_t inode_offset = (inode_num - 1) % superblock.s_inodes_per_group;
    inode_offset *= superblock.s_inode_size;

    if (ext2_read_bgd(disk, partition_offset, superblock, block_group, &bgd))
    {
        fprintf(stderr, "Error retrieving block group descriptor %"PRIu64".\n", block_group);
        return -1;
    }

    inode_table_offset = ext2_block_offset(bgd.bg_inode_table, superblock);

    if (fseeko(disk, partition_offset + inode_table_offset + inode_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                                  partition_offset + inode_table_offset +
                                  inode_offset);
        return -1;
    }

    if (fread(inode, 1, sizeof(struct ext2_inode), disk) != sizeof(struct ext2_inode))
    {
        fprintf_light_red(stdout, "Error while trying to read ext2 inode.\n");
        return -1;
    }

    fprintf_cyan(stdout, "Analyzing inode @sector: %"PRId64" @offset: %"PRId64
                         ".\n", (partition_offset + inode_table_offset +
                         inode_offset) / SECTOR_SIZE, (partition_offset +
                         inode_table_offset + inode_offset) % SECTOR_SIZE);

    return 0;
}

int ext2_read_file_block(FILE* disk, int64_t partition_offset,
                         struct ext2_superblock superblock, uint32_t block_num,
                         struct ext2_inode inode, uint32_t* buf)
{
    uint32_t block_size = ext2_block_size(superblock);
    uint32_t addresses_in_block = block_size / 4;
    
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

        ext2_read_block(disk, partition_offset, superblock,
                        inode.i_block[block_num], (uint8_t*) buf);
        return 0;
    }

    /* INDIRECT */
    if (block_num <= indirect_high)
    {
        block_num -= indirect_low; /* rebase, 0 is beginning indirect block range */
        
        if (inode.i_block[12] == 0)
            return 1; /* finished */

        ext2_read_block(disk, partition_offset, superblock, inode.i_block[12],
                        (uint8_t*) buf);

        if (buf[block_num] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, superblock, buf[block_num],
                        (uint8_t*) buf);
        return 0;
    }

    /* DOUBLE */
    if (block_num <= double_high)
    {
        block_num -= double_low;

        if (inode.i_block[13] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* double */
                        superblock, inode.i_block[13], (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* real */
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

        ext2_read_block(disk, partition_offset, /* triple */
                        superblock, inode.i_block[14], (uint8_t*) buf);

        if (buf[block_num / (addresses_in_block*addresses_in_block)] == 0)
            return 1;
        
        ext2_read_block(disk, partition_offset, /* double */
                        superblock,
                        buf[block_num / (addresses_in_block*addresses_in_block)],
                        (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],  
                        (uint8_t*) buf);

        return 0;
    }

    return -1;
}

int ext2_read_file_block_sectors(FILE* disk, int64_t partition_offset,
                                 struct ext2_superblock superblock, uint32_t block_num,
                                 struct ext2_inode inode, uint32_t* buf)
{
    uint32_t block_size = ext2_block_size(superblock);
    uint32_t addresses_in_block = block_size / 4;
    
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
                                ext2_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext2_read_block(disk, partition_offset, superblock,
                        inode.i_block[block_num], (uint8_t*) buf);
        return 0;
    }

    /* INDIRECT */
    if (block_num <= indirect_high)
    {
        block_num -= indirect_low; /* rebase, 0 is beginning indirect block range */
        
        if (inode.i_block[12] == 0)
            return 1; /* finished */

        ext2_read_block(disk, partition_offset, superblock, inode.i_block[12],
                        (uint8_t*) buf);

        if (buf[block_num] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num] *
                                ext2_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext2_read_block(disk, partition_offset, superblock, buf[block_num],
                        (uint8_t*) buf);
        return 0;
    }

    /* DOUBLE */
    if (block_num <= double_high)
    {
        block_num -= double_low;

        if (inode.i_block[13] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* double */
                        superblock, inode.i_block[13], (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num % addresses_in_block] *
                                ext2_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext2_read_block(disk, partition_offset, /* real */
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

        ext2_read_block(disk, partition_offset, /* triple */
                        superblock, inode.i_block[14], (uint8_t*) buf);

        if (buf[block_num / (addresses_in_block*addresses_in_block)] == 0)
            return 1;
        
        ext2_read_block(disk, partition_offset, /* double */
                        superblock,
                        buf[block_num / (addresses_in_block*addresses_in_block)],
                        (uint8_t*) buf);

        if (buf[block_num / addresses_in_block] == 0)
            return 1;

        ext2_read_block(disk, partition_offset, /* indirect */
                        superblock, buf[block_num / addresses_in_block],
                        (uint8_t*) buf);

        if (buf[block_num % addresses_in_block] == 0)
            return 1;

        fprintf_yellow(stderr, "bst_insert(tree, %"PRId64", (void*) 1);\n",
                                (buf[block_num % addresses_in_block] *
                                ext2_block_size(superblock) +
                                partition_offset) / SECTOR_SIZE);
        ext2_read_block(disk, partition_offset, /* real */
                        superblock, buf[block_num % addresses_in_block],  
                        (uint8_t*) buf);

        return 0;
    }

    return -1;
}

int ext2_read_dir_entry(uint8_t* buf, struct ext2_dir_entry* dir)
{
    memcpy(dir, buf, sizeof(struct ext2_dir_entry));
    return 0;
}

uint64_t ext2_file_size(struct ext2_inode inode)
{
    uint64_t total_size = ((uint64_t) inode.i_dir_acl) << 32;
    total_size |= inode.i_size;
    return total_size;
}

/* recursive function listing a tree rooted at some directory.
 * recursion ends at leaf files.
 * depth-first
 */
int ext2_list_tree(FILE* disk, int64_t partition_offset, 
                   struct ext2_superblock superblock,
                   struct ext2_inode root_inode,
                   char* prefix)
{
    struct ext2_inode child_inode;
    struct ext2_dir_entry dir;
    uint64_t block_size = ext2_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192];

    if (root_inode.i_mode & 0x8000) /* file, no dir entries more */
        return 0;

    if (ext2_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext2_file_size(root_inode) / block_size;
        if (ext2_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext2_read_file_block(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);
        
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

            if (ext2_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
                return 0;

            if (ext2_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
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
                    fprintf_red(stdout, "%s\n", path);
                }
                ext2_list_tree(disk, partition_offset, superblock, child_inode,
                               strcat(path, "/")); /* recursive call */
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext2_list_root_fs(FILE* disk, int64_t partition_offset,
                      struct ext2_superblock superblock, char* prefix)
{
    struct ext2_inode root;
    if (ext2_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    fprintf_yellow(stdout, "inode 2 %s\n", prefix);

    if (ext2_list_tree(disk, partition_offset, superblock, root, prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int ext2_reconstruct_file_sectors(FILE* disk, int64_t partition_offset,
                                  struct ext2_superblock superblock, 
                                  struct ext2_inode inode, char* copy_path)
{
    uint64_t block_size = ext2_block_size(superblock),
             file_size = ext2_file_size(inode);
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
        ret_check = ext2_read_file_block_sectors(disk, partition_offset, superblock, i,
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

int ext2_reconstruct_file(FILE* disk, int64_t partition_offset,
                          struct ext2_superblock superblock, 
                          struct ext2_inode inode, char* copy_path)
{
    FILE* copy;
    uint64_t block_size = ext2_block_size(superblock),
             file_size = ext2_file_size(inode);
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
        ret_check = ext2_read_file_block(disk, partition_offset, superblock, i,
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
int ext2_reconstruct_tree(FILE* disk, int64_t partition_offset, 
                          struct ext2_superblock superblock,
                          struct ext2_inode root_inode,
                          char* prefix,
                          char* copy_prefix)
{
    struct ext2_inode child_inode;
    struct ext2_dir_entry dir;
    uint64_t block_size = ext2_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192], copy[8192];

    if (root_inode.i_mode & 0x8000) /* file, no dir entries more */
    {
        strcpy(copy, copy_prefix);
        prefix[strlen(prefix)-1] = '\0'; /* remove trailing slash */
        strcat(copy, prefix);
        fprintf_light_red(stdout, "Creating file: %s\n", copy);
        ext2_reconstruct_file(disk, partition_offset, superblock, root_inode,
                              copy);
        return 0;
    }
    else if (root_inode.i_mode & 0x4000)
    {
        strcpy(copy, copy_prefix);
        strcat(copy, prefix);
        fprintf_light_red(stdout, "Creating dir: %s\n", copy);
        mkdir(copy, ext2_inode_mode(root_inode.i_mode));
    }

    if (ext2_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext2_file_size(root_inode) / block_size;
        if (ext2_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext2_read_file_block(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);
        
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

            if (ext2_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
                return 0;

            if (ext2_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
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
                ext2_reconstruct_tree(disk, partition_offset, superblock,
                                      child_inode, strcat(path, "/"), copy_prefix); /* recursive call */
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext2_reconstruct_root_fs(FILE* disk, int64_t partition_offset,
                             struct ext2_superblock superblock, char* prefix,
                             char* copy_prefix)
{
    struct ext2_inode root;
    if (ext2_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    if (ext2_reconstruct_tree(disk, partition_offset, superblock, root,
                              prefix, copy_prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int ext2_print_file_sectors(FILE* disk, int64_t partition_offset,
                            struct ext2_superblock superblock, 
                            struct ext2_inode inode, char* copy_path)
{
    FILE* copy;
    uint64_t block_size = ext2_block_size(superblock),
             file_size = ext2_file_size(inode);
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
        ret_check = ext2_read_file_block(disk, partition_offset, superblock, i,
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
int ext2_print_tree_sectors(FILE* disk, int64_t partition_offset, 
                            struct ext2_superblock superblock,
                            struct ext2_inode root_inode,
                            char* prefix,
                            char* copy_prefix)
{
    struct ext2_inode child_inode;
    struct ext2_dir_entry dir;
    uint64_t block_size = ext2_block_size(superblock), position = 0;
    uint8_t buf[block_size];
    uint64_t num_blocks;
    uint64_t i;
    int ret_check;
    char path[8192], copy[8192];

    if (root_inode.i_mode & 0x8000) /* file, no dir entries more */
    {
        ext2_reconstruct_file_sectors(disk, partition_offset, superblock, root_inode,
                                      copy);
        return 0;
    }
    else if (root_inode.i_mode & 0x4000)
    {
    }

    if (ext2_file_size(root_inode) == 0)
    {
        num_blocks = 0;
    }
    else
    {
        num_blocks = ext2_file_size(root_inode) / block_size;
        if (ext2_file_size(root_inode) % block_size != 0)
            num_blocks += 1;
    }

    /* go through each valid block of the inode */
    for (i = 0; i < num_blocks; i++)
    {
        ret_check = ext2_read_file_block_sectors(disk, partition_offset, superblock, i, root_inode, (uint32_t*) buf);
        
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

            if (ext2_read_dir_entry(&buf[position], &dir))
            {
                fprintf_light_red(stderr, "Error reading dir entry from block.\n");
                return -1;
            }

            if (dir.inode == 0)
                return 0;

            if (ext2_read_inode(disk, partition_offset, superblock, dir.inode, &child_inode))
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
                ext2_print_tree_sectors(disk, partition_offset, superblock,
                                      child_inode, strcat(path, "/"), copy_prefix); /* recursive call */
                fprintf_yellow(stderr, "};\n");
            }

            position += dir.rec_len;
        }
    }

    return 0;
}

int ext2_print_root_fs_sectors(FILE* disk, int64_t partition_offset,
                               struct ext2_superblock superblock, char* prefix,
                               char* copy_prefix)
{
    struct ext2_inode root;
    if (ext2_read_inode(disk, partition_offset, superblock, 2, &root))
    {
        fprintf(stderr, "Failed getting root fs inode.\n");
        return -1;
    }

    fprintf_light_blue(stdout, "inode %"PRIu32" dir %s\n", (uint32_t) 2, prefix);

    if (ext2_print_tree_sectors(disk, partition_offset, superblock, root,
                                prefix, copy_prefix))
    {
        fprintf(stdout, "Error listing fs tree from root inode.\n");
        return -1;
    }

    return 0;
}

int print_inode_mode(uint16_t i_mode)
{
    fprintf_yellow(stdout, "\t(  ");

    /* file format */
    if ((i_mode & 0xc000) == 0xc000)
        fprintf_blue(stdout, "EXT2_S_IFSOCK | ");
    if ((i_mode & 0xa000) == 0xa000)
        fprintf_blue(stdout, "EXT2_S_IFLNK | ");
    if (i_mode & 0x8000)
        fprintf_blue(stdout, "EXT2_S_IFREG | ");
    if ((i_mode & 0x6000) == 0x6000)
        fprintf_blue(stdout, "EXT2_S_IFBLK | ");
    if (i_mode & 0x4000)
        fprintf_blue(stdout, "EXT2_S_IFDIR | ");
    if (i_mode & 0x2000)
        fprintf_blue(stdout, "EXT2_S_IFCHR | ");
    if (i_mode & 0x1000)
        fprintf_blue(stdout, "EXT2_S_IFIFO | ");

    /* process execution/group override */
    if (i_mode & 0x0800)
        fprintf_blue(stdout, "EXT2_S_ISUID | ");
    if (i_mode & 0x0400)
        fprintf_blue(stdout, "EXT2_S_ISGID | ");
    if (i_mode & 0x0200)
        fprintf_blue(stdout, "EXT2_S_ISVTX | ");

    /* access control */
    if (i_mode & 0x0100)
        fprintf_blue(stdout, "EXT2_S_IRUSR | ");
    if (i_mode & 0x0080)
        fprintf_blue(stdout, "EXT2_S_IWUSR | ");
    if (i_mode & 0x0040)
        fprintf_blue(stdout, "EXT2_S_IXUSR | ");
    if (i_mode & 0x0020)
        fprintf_blue(stdout, "EXT2_S_IRGRP | ");
    if (i_mode & 0x0010)
        fprintf_blue(stdout, "EXT2_S_IWGRP | ");
    if (i_mode & 0x0008)
        fprintf_blue(stdout, "EXT2_S_IXGRP | ");
    if (i_mode & 0x0004)
        fprintf_blue(stdout, "EXT2_S_IROTH | ");
    if (i_mode & 0x0002)
        fprintf_blue(stdout, "EXT2_S_IWOTH | ");
    if (i_mode & 0x0001)
        fprintf_blue(stdout, "EXT2_S_IXOTH | ");


    fprintf_yellow(stdout, "\b\b )\n");
    return 0;
}

int print_inode_flags(uint16_t i_flags)
{
    fprintf_yellow(stdout, "\t(  ");
    if (i_flags & 0x1)
        fprintf_blue(stdout, "EXT2_SECRM_FL | ");
    if (i_flags & 0x2)
        fprintf_blue(stdout, "EXT2_UNRM_FL | ");    
    if (i_flags & 0x4)
        fprintf_blue(stdout, "EXT2_COMPR_FL | ");
    if (i_flags & 0x8)
        fprintf_blue(stdout, "EXT2_SYNC_FL | ");

    /* compression */
    if (i_flags & 0x10)
        fprintf_blue(stdout, "EXT2_IMMUTABLE_FL | ");
    if (i_flags & 0x20)
        fprintf_blue(stdout, "EXT2_APPEND_FL | ");
    if (i_flags & 0x40)
        fprintf_blue(stdout, "EXT2_NODUMP_FL | ");
    if (i_flags & 0x80)
        fprintf_blue(stdout, "EXT2_NOATIME_FL | ");

    if (i_flags & 0x100)
        fprintf_blue(stdout, "EXT2_DIRTY_FL | ");
    if (i_flags & 0x200)
        fprintf_blue(stdout, "EXT2_COMPRBLK_FL | ");
    if (i_flags & 0x400)
        fprintf_blue(stdout, "EXT2_NOCOMPR_FL | ");
    if (i_flags & 0x800)
        fprintf_blue(stdout, "EXT2_ECOMPR_FL | ");

    if (i_flags & 0x1000)
        fprintf_blue(stdout, "EXT2_BTREE_FL | ");
    if (i_flags & 0x2000)
        fprintf_blue(stdout, "EXT2_INDEX_FL | ");
    if (i_flags & 0x4000)
        fprintf_blue(stdout, "EXT2_IMAGIC_FL | ");
    if (i_flags & 0x8000)
        fprintf_blue(stdout, "EXT3_JOURNAL_DATA_FL | ");

    if (i_flags & 0x80000000)
        fprintf_blue(stdout, "EXT2_RESERVED_FL | ");

   fprintf_yellow(stdout, "\b\b )\n");
   return 0;
}

int print_ext2_inode_osd2(uint8_t osd2[12])
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

int print_inode_permissions(uint16_t i_mode)
{
    fprintf_yellow(stdout, "\tPermissions: 0%"PRIo16"\n", i_mode &
                                             (0x01c0 | 0x0038 | 0x007));
    return 0;
}

int ext2_print_inode(struct ext2_inode inode)
{
    int ret = 0;
    fprintf_yellow(stdout, "i_mode: 0x%"PRIx16"\n",
                           inode.i_mode);
    print_inode_mode(inode.i_mode);
    print_inode_permissions(inode.i_mode);
    if (inode.i_mode & 0x4000)
        ret = inode.i_block[0];
    fprintf_yellow(stdout, "i_uid: %"PRIu16"\n",
                           inode.i_uid);
    fprintf_yellow(stdout, "i_size: %"PRIu32"\n",
                           inode.i_size);
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
                           inode.i_blocks);
    fprintf_yellow(stdout, "i_flags: %"PRIu32"\n",
                           inode.i_flags);
    print_inode_flags(inode.i_flags);
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
    fprintf_yellow(stdout, "i_file_acl: 0%.3"PRIo32"\n",
                           inode.i_file_acl);
    fprintf_yellow(stdout, "i_dir_acl: 0%.3"PRIo32"\n",
                           inode.i_dir_acl);
    fprintf_yellow(stdout, "i_faddr: %"PRIu32"\n",
                           inode.i_faddr);
    print_ext2_inode_osd2(inode.i_osd2);
    return ret;
}

int print_ext2_block_group_descriptor(struct ext2_block_group_descriptor bgd)
{
    fprintf_light_cyan(stdout, "--- Analyzing Block Group Descriptor ---\n");
    fprintf_yellow(stdout, "bg_block_bitmap: %"PRIu32"\n",
                           bgd.bg_block_bitmap);
    fprintf_yellow(stdout, "bg_inode_bitmap: %"PRIu32"\n",
                           bgd.bg_inode_bitmap);
    fprintf_yellow(stdout, "bg_inode_table: %"PRIu32"\n",
                           bgd.bg_inode_table);
    fprintf_yellow(stdout, "bg_free_blocks_count: %"PRIu16"\n",
                           bgd.bg_free_blocks_count);
    fprintf_yellow(stdout, "bg_free_inodes_count: %"PRIu16"\n",
                           bgd.bg_free_inodes_count);
    fprintf_yellow(stdout, "bg_used_dirs_count: %"PRIu16"\n",
                           bgd.bg_used_dirs_count);
    /* uint16_t bg_pad; */
    /* uint8_t bg_reserved[12]; */
    return 0;
}

int print_ext2_superblock(struct ext2_superblock superblock)
{
    fprintf_yellow(stdout, "s_inodes_count: %"PRIu32"\n",
                           superblock.s_inodes_count);
    fprintf_yellow(stdout, "s_blocks_count: %"PRIu32"\n",
                           superblock.s_blocks_count);
    fprintf_yellow(stdout, "s_r_blocks_count: %"PRIu32"\n",
                           superblock.s_r_blocks_count);
    fprintf_yellow(stdout, "s_free_blocks_count: %"PRIu32"\n",
                           superblock.s_free_blocks_count);
    fprintf_yellow(stdout, "s_free_inodes_count: %"PRIu32"\n",
                           superblock.s_free_inodes_count);
    fprintf_yellow(stdout, "s_first_data_block: %"PRIu32"\n",
                           superblock.s_first_data_block);
    fprintf_yellow(stdout, "s_log_block_size: %"PRIu32"\n",
                           superblock.s_log_block_size);
    fprintf_yellow(stdout, "s_log_frag_size: %"PRIu32"\n",
                           superblock.s_log_frag_size);
    fprintf_yellow(stdout, "s_blocks_per_group: %"PRIu32"\n",
                           superblock.s_blocks_per_group);
    fprintf_yellow(stdout, "s_frags_per_group: %"PRIu32"\n",
                           superblock.s_frags_per_group);
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
        fprintf_light_green(stdout, "Magic value matches EXT_SUPER_MAGIC\n"); 
    }
    else
    {
        fprintf_light_red(stdout, "Magic value does not match EXT_SUPER_MAGIC\n");
    }
    fprintf_yellow(stdout, "s_state: %"PRIu16"\n",
                           superblock.s_state);
    fprintf_light_yellow(stdout, "File System State: %s\n",
                                 s_state_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_errors: %"PRIu16"\n",
                           superblock.s_errors);
    fprintf_light_yellow(stdout, "Error State: %s\n",
                                 s_errors_LUT[superblock.s_state]);
    fprintf_yellow(stdout, "s_minor_rev_level: %"PRIu16"\n",
                           superblock.s_minor_rev_level);
    fprintf_yellow(stdout, "s_lastcheck: %"PRIu32"\n",
                           superblock.s_lastcheck);
    fprintf_yellow(stdout, "s_checkinterval: %"PRIu32"\n",
                           superblock.s_checkinterval);
    fprintf_yellow(stdout, "s_creator_os: %"PRIu32"\n",
                           superblock.s_creator_os);
    fprintf_light_yellow(stdout, "Resolved OS: %s\n",
                                 s_creator_os_LUT[superblock.s_creator_os]);
    fprintf_yellow(stdout, "s_rev_level: %"PRIu32"\n",
                           superblock.s_rev_level);
    fprintf_light_yellow(stdout, "Revision Level: %s\n",
                                 s_rev_level_LUT[superblock.s_rev_level]);
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
                           superblock.s_algo_bitmap);
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
                           superblock.s_default_mount_options);
    fprintf_yellow(stdout, "s_first_meta_bg: %"PRIu32"\n",
                           superblock.s_first_meta_bg);
    return 0;
}

int ext2_probe(FILE* disk, int64_t partition_offset, struct ext2_superblock* superblock)
{
    if (partition_offset == 0)
    {
        fprintf_light_red(stderr, "ext2 probe failed on partition at offset: "
                                  "0x%.16"PRIx64".\n", partition_offset);
        return -1;
    }

    partition_offset += EXT2_SUPERBLOCK_OFFSET;

    if (fseeko(disk, partition_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%.16"PRIx64".\n",
                                  partition_offset);
        return -1;
    }

    if (fread(superblock, 1, sizeof(struct ext2_superblock), disk) !=
        sizeof(struct ext2_superblock))
    {
        fprintf_light_red(stderr, 
                          "Error while trying to read ext2 superblock.\n");
        return -1;
    }

    if (superblock->s_magic != 0xef53)
    {
        fprintf_light_red(stderr, "ext2 superblock s_magic mismatch.\n");
        return -1;
    }

    return 0;
}

int ext2_list_block_groups(FILE* disk, int64_t partition_offset,
                           struct ext2_superblock superblock)
{
    struct ext2_block_group_descriptor bgd;

    while (ext2_next_block_group_descriptor(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_ext2_block_group_descriptor(bgd))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
       fprintf(stdout, "\n");
    }
    return 0;
}

int ext2_list_block_groups_sectors(FILE* disk, int64_t partition_offset,
                                   struct ext2_superblock superblock)
{
    struct ext2_block_group_descriptor bgd;

    while (ext2_next_block_group_descriptor_sectors(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_ext2_block_group_descriptor(bgd))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
    }
    return 0;
}

int print_sectors_ext2_block_group_descriptor(int64_t offset, struct ext2_block_group_descriptor bgd, struct ext2_superblock superblock)
{
    uint32_t block_size = ext2_block_size(superblock);
    fprintf_yellow(stdout, "bg_block_bitmap sector %"PRId64"\n",
                           (bgd.bg_block_bitmap * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_bitmap sector %"PRIu32"\n",
                           (bgd.bg_inode_bitmap * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_table sector start %"PRIu32"\n",
                           (bgd.bg_inode_table * block_size + offset) / SECTOR_SIZE);
    fprintf_yellow(stdout, "bg_inode_table sector end %"PRIu32"\n",
                            (bgd.bg_inode_table * block_size + offset + superblock.s_inodes_per_group * sizeof(struct ext2_inode)) / SECTOR_SIZE);
    fprintf_yellow(stdout, "BGD end sector %"PRId64"\n",
                           (bgd.bg_block_bitmap * block_size + offset + superblock.s_blocks_per_group * block_size) / SECTOR_SIZE);
    return 0;
}

int ext2_print_sectormap(FILE* disk, int64_t partition_offset,
                         struct ext2_superblock superblock)
{
    /* print superblock sector */
    fprintf_yellow(stdout, "Superblock sector %"PRId64"\n", (partition_offset + EXT2_SUPERBLOCK_OFFSET) / SECTOR_SIZE);

    /* walk block group descriptor table */
    struct ext2_block_group_descriptor bgd;

    while (ext2_next_block_group_descriptor(disk, partition_offset, superblock, &bgd) > 0)
    {
       if (print_sectors_ext2_block_group_descriptor(partition_offset, bgd, superblock))
       {
           fprintf_light_red(stderr, "Failed printing block group descriptor.\n");
           return -1;
       }
    }

    /* walk inode table */
    ext2_print_root_fs_sectors(disk, partition_offset, superblock, "/", ""); 
    return 0;
}
