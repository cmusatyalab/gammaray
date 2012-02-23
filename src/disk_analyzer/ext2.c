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

uint32_t compute_block_offset(uint32_t first_block_group_offset,
                             uint32_t block_size,
                             uint32_t block_num)
{
    return first_block_group_offset + block_size * block_num;
}

int read_block(FILE* disk, uint32_t partition_offset, uint32_t block_size,
               uint32_t block, uint8_t* buf)
{
    uint32_t offset = compute_block_offset(partition_offset, block_size, 
                                          block);

   if (fseek(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n", 
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

int reconstruct_file(FILE* disk, FILE* dest, struct ext2_inode inode,
                     uint32_t partition_offset, uint32_t block_size)
{
    /* total file size */
    int i, j, k;
    uint64_t total_size = ((uint64_t) inode.i_dir_acl) << 32;
    total_size |= inode.i_size;
    uint8_t buf[block_size];
    uint32_t indirect_buf[block_size], double_buf[block_size],
             treble_buf[block_size];

    /* block positions 0-11 are direct */
    for (i = 0; i < 12; i++)
    {
        if (inode.i_block[i] == 0)
            return 0;

        if (read_block(disk, partition_offset, block_size, inode.i_block[i],
                       buf))
        {
            fprintf_light_red(stderr, "Error reading direct block %"PRIu32
                                      "\n", inode.i_block[i]);
            return -1;
        }

        total_size = write_block(dest, total_size, block_size, buf);
        
        if (total_size < 0)
        {
            fprintf_light_red(stderr, "Error while writing direct block.\n");
            return -1;
        }

        if (total_size == 0)
            return 0;
    }

    /* block position 12 is indirect */
    if (inode.i_block[i] == 0)
        return 0;

    if (read_block(disk, partition_offset, block_size, inode.i_block[i++],
                   (uint8_t*) indirect_buf))
    {
        fprintf_light_red(stderr, "Error reading direct block %"PRIu32
                                  "\n", inode.i_block[--i]);
        return -1;
    }

    for (j = 0; j < (block_size / sizeof(uint32_t)); j++)
    {
        if (indirect_buf[j] == 0)
            return 0;

        if(read_block(disk, partition_offset, block_size,
                      indirect_buf[j], buf))
        {
            fprintf_light_red(stderr, "Error reading direct block %"PRIu32
                                      "\n");
            return -1;
        }

        total_size = write_block(dest, total_size, block_size, buf);
        
        if (total_size < 0)
        {
            fprintf_light_red(stderr, "Error while writing direct block.\n");
            return -1;
        }

        if (total_size == 0)
            return 0;
    }

    /* block position 13 is doubly indirect */
    if (inode.i_block[i] == 0)
        return 0;

    if (read_block(disk, partition_offset, block_size, inode.i_block[i++],
                   (uint8_t*) double_buf))
    {
        fprintf_light_red(stderr, "Error reading direct block %"PRIu32
                                  "\n", inode.i_block[--i]);
        return -1;
    }

    for (j = 0; j < (block_size / sizeof(uint32_t)); j++)
    {
        if (double_buf[j] == 0)
            return 0;

        if(read_block(disk, partition_offset, block_size,
                      double_buf[j], (uint8_t*) indirect_buf))
        {
            fprintf_light_red(stderr, "Error reading indirect block %"PRIu32
                                      "\n", double_buf[j]);
            return -1;
        }

        for (k = 0; k < (block_size / sizeof(uint32_t)); k++)
        {
            if (indirect_buf[k] == 0)
                return 0;

            if(read_block(disk, partition_offset, block_size,
                          indirect_buf[k], (uint8_t*) buf))
            {
                fprintf_light_red(stderr, "Error reading indirect block %"PRIu32
                                          "\n", indirect_buf[k]);
                return -1;
            }

            total_size = write_block(dest, total_size, block_size, buf);
            
            if (total_size < 0)
            {
                fprintf_light_red(stderr, "Error while writing direct block.\n");
                return -1;
            }

            if (total_size == 0)
                return 0;
        }
    }

    /* block position 14 is trebly indirect */
    if (inode.i_block[i] == 0)
        return 0;

    if (read_block(disk, partition_offset, block_size, inode.i_block[i],
                   (uint8_t*) treble_buf))
    {
        fprintf_light_red(stderr, "Error reading direct block %"PRIu32
                                  "\n", inode.i_block[i]);
        return -1;
    }

    for (i = 0; i < (block_size / sizeof(uint32_t)); i++)
    {
        if (treble_buf[i] == 0)
            return 0;

        if(read_block(disk, partition_offset, block_size,
                      treble_buf[i], (uint8_t*) double_buf))
        {
            fprintf_light_red(stderr, "Error reading indirect block %"PRIu32
                                      "\n", treble_buf[i]);
            return -1;
        }

        for (j = 0; j < (block_size / sizeof(uint32_t)); j++)
        {
            if (double_buf[j] == 0)
                return 0;

            if(read_block(disk, partition_offset, block_size,
                          double_buf[j], (uint8_t*) indirect_buf))
            {
                fprintf_light_red(stderr, "Error reading indirect block %"PRIu32
                                          "\n", double_buf[j]);
                return -1;
            }

            for (k = 0; k < (block_size / sizeof(uint32_t)); k++)
            {
                if (indirect_buf[k] == 0)
                    return 0;

                if(read_block(disk, partition_offset, block_size,
                              indirect_buf[k], (uint8_t*) buf))
                {
                    fprintf_light_red(stderr, "Error reading indirect block %"PRIu32
                                              "\n", indirect_buf[k]);
                    return -1;
                }

                total_size = write_block(dest, total_size, block_size, buf);
                
                if (total_size < 0)
                {
                    fprintf_light_red(stderr, "Error while writing direct block.\n");
                    return -1;
                }

                if (total_size == 0)
                    return 0;
            }
        }
    }
    return 0;
}

int print_ext2_dir_entry(uint32_t entry, struct ext2_dir_entry dir)
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

int print_ext2_dir_entries(uint8_t* bytes, uint32_t len)
{
    uint32_t i;
    uint32_t num_entries = len / sizeof(struct ext2_dir_entry);

    for (i = 0; i < num_entries; i++)
        print_ext2_dir_entry(i, *((struct ext2_dir_entry*)
                                  (bytes + i*sizeof(struct ext2_dir_entry))));
    return 0;
}

int read_inode(FILE* disk, uint32_t inode_table_offset,
               uint32_t inode_number, struct ext2_inode* inode)
{
   if (fseek(disk, inode_table_offset + (inode_number-1)*256, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          inode_table_offset);
        return -1;
    }

    if (fread(inode, 1, sizeof(struct ext2_inode), disk) != sizeof(struct ext2_inode))
    {
        fprintf_light_red(stdout, "Error while trying to read ext2 inode.\n");
        return -1;
    }

    return 0;
}

int read_dir_entry(uint32_t offset, FILE* disk, struct ext2_dir_entry* dir)
{
   if (fseek(disk, offset, 0))
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

mode_t get_inode_mode(uint16_t i_mode)
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

/* depth first find */
int simple_find(uint32_t inode_table_offset,
                FILE* disk, uint32_t inode_number, char* path_prefix)
{
    /* go inode by inode */
    struct ext2_inode inode;
    struct ext2_dir_entry dir;
    char path[4096] = {0}, reconstructed[4096] = {'/','t','m','p','/','\0'};
    uint16_t dir_entry_offset = 0, total_offset = 0;
    uint32_t dir_block = 0;
    uint32_t block_group_offset = 32768*(1024<<2)*((inode_number - 1) / 8192);
    //fprintf_light_cyan(stdout, "inode table offset: 0x%"PRIx32" inode: %"PRIu32"\n",
    //                           inode_table_offset, inode_number);
    
    /* start crawling root inode */
    read_inode(disk, inode_table_offset+block_group_offset, inode_number % 8192,
               &inode);
    //print_ext2_inode(inode);
    dir_block = inode.i_block[0];
    
    /* create folder */
    if (inode.i_mode & 0x4000)
    {
        if (path_prefix[1])
        {
            strcat(reconstructed, &(path_prefix[1]));
            fprintf_light_red(stdout, "Creating dir: %s\n", reconstructed);
            mkdir(reconstructed, get_inode_mode(inode.i_mode));
        }
    }
    
    /* reconstruct file for debugging */
    if (inode.i_mode & 0x8000)
    {
        strcat(reconstructed, &(path_prefix[1]));
        reconstructed[strlen(reconstructed) - 1] = '\0';
        FILE* dest = fopen(reconstructed, "wb");

        if (dest == NULL)
        {
            fprintf_light_red(stderr, "Failed opening reconstruction file %s."
                                      "\n", reconstructed);
            return -1;
        }

        if (reconstruct_file(disk, dest, inode, 0x7e00, 1024<<2))
        {
            fprintf_light_red(stderr, "Reconstructing file failed.");
            fclose(dest);
            return -1;
        }

        fprintf_light_yellow(stdout, "Reconstructed file: %s\n",
                                     reconstructed);

        fclose(dest);
        return 0;
    }

    if (dir_block == 0)
        return 0;

    while(total_offset < (1024<<2))
    {
        //fprintf_light_red(stdout, "reading data block: %"PRIu32"\n", dir_block);
        dir_entry_offset = read_dir_entry(0x7e00 + (1024<<2)*(dir_block%32768) +
                                          total_offset + block_group_offset, disk, &dir);
        total_offset += dir_entry_offset;

        if (strcmp((const char *) dir.name, ".") == 0 ||
            strcmp((const char *) dir.name, "..") == 0)
            continue;

        //print_ext2_dir_entry(0, dir);
        //fprintf_light_red(stdout, "total_offset: %"PRIu16"\n", total_offset);
        strcpy(path, path_prefix);
        strcat(path, (char*) dir.name);
        fprintf_yellow(stdout, "%s\n", path);

        strcat(path, "/");
        //fprintf_light_red(stdout, "recursing deeper...inode: %"PRIu32"\n", dir.inode);
        //read_inode(disk, inode_table_offset+block_group_offset, inode_number % 1136, &inode);
        //print_ext2_inode(inode);

        simple_find(inode_table_offset, disk, dir.inode, path);
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

int print_ext2_inode(struct ext2_inode inode)
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
