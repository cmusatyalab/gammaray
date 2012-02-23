/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a raw disk image and produce summary datastructures of   *
 *          the partition table, and file system metadata.                   *
 *                                                                           *
 *****************************************************************************/

#define _FILE_OFFSET_BITS 64
#define UINT_16(s) (uint16_t) s
#define UINT_32(i) (uint32_t) i

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "color.h"
#include "ext2.h"
#include "mbr.h"

int analyze_ext2_superblock(FILE * disk, long int offset)
{
    struct ext2_superblock superblock;
    fprintf_light_cyan(stdout, "\n\nAnalyzing ext2 Superblock at Position "
                               "0x%lx\n", offset);

    if (fseek(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
    }

    if (fread(&superblock, 1, sizeof(struct ext2_superblock), disk) !=
        sizeof(struct ext2_superblock))
    {
        fprintf_light_red(stdout, 
                          "Error while trying to read ext2 superblock.\n");
        return EXIT_FAILURE;
    }

    print_ext2_superblock(superblock);

    return EXIT_SUCCESS;
}

int analyze_ext2_block_group_descriptor(FILE * disk, long int offset)
{
    struct ext2_block_group_descriptor bgd;
    fprintf_light_cyan(stdout, "\n\nAnalyzing ext2 Block Group Descriptor at "
                               "Position 0x%lx\n", offset);

    if (fseek(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
    }

    if (fread(&bgd, 1, sizeof(struct ext2_block_group_descriptor), disk) !=
        sizeof(struct ext2_block_group_descriptor))
    {
        fprintf_light_red(stdout, 
                          "Error while trying to read ext2 Block Group "
                          "Descriptor.\n");
        return EXIT_FAILURE;
    }

    print_ext2_block_group_descriptor(bgd);

    return EXIT_SUCCESS;
}

int analyze_ext2_inode_table(FILE * disk, long int offset)
{
    int ret = 0;
    struct ext2_inode inode;
    fprintf_light_cyan(stdout, "\n\nAnalyzing ext2 inode Table at "
                               "Position 0x%lx\n", offset);

    if (fseek(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
    }

    if (fread(&inode, 1, sizeof(struct ext2_inode), disk) !=
        sizeof(struct ext2_inode))
    {
        fprintf_light_red(stdout, "Error while trying to read ext2 inode.\n");
        return EXIT_FAILURE;
    }

    ret = print_ext2_inode(inode);

    return ret;
}

int analyze_ext2_dir_entries(FILE * disk, long int offset)
{

    uint8_t buf[1024];
    fprintf_light_cyan(stdout, "\n\nAnalyzing ext2 dir entries at "
                               "Position 0x%lx\n", offset);

    if (fseek(disk, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n",
                          offset);
    }

    if (fread(buf, 1, 1024, disk) != 1024)
    {
        fprintf_light_red(stdout, "Error while trying to read ext2 data "
                                  "block.\n");
        return EXIT_FAILURE;
    }

    print_ext2_dir_entries(buf, 1024);

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk;
    struct mbr mbr;
    //struct ext2_superblock ext2_superblock;
    int64_t partition_offset;

    fprintf_blue(stdout, "Raw Disk Analyzer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: ./%s <raw disk file>\n", args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing Disk: %s\n\n", args[1]);

    disk = fopen(args[1], "r");
    
    if (disk == NULL)
    {
        fprintf_light_red(stderr, "Error opening raw disk file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    if (parse_mbr(disk, &mbr))
    {
        fprintf_light_red(stdout, "Error reading MBR from disk.  Aborting\n");
        return EXIT_FAILURE;
    }

    print_mbr(mbr);
    while ((partition_offset = next_partition_offset(mbr)) >= 0)
    {
        //if (ext2_probe(ext2_superblock))
        //{
        //}
    }

    /* MBR sector size constant 512 bytes */
    //analyze_ext2_superblock(disk, 0x7e00 + 1024); /* Computation: sector size * LBA of first sector = 0x7e00) */
    //analyze_ext2_block_group_descriptor(disk, 0x7e00 + (1024<<2));
    //fprintf_light_cyan(stdout, "\nBad Blocks Inode");
    //analyze_ext2_inode_table(disk, 0x7e00 + (1024<<2)*643);
    //fprintf_light_cyan(stdout, "\nRoot Directory Inode");
    //analyze_ext2_inode_table(disk, 0x7e00 + (1024<<2)*643 + 256);
/*    if (ret)
    {
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*ret);
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*ret + 12);
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*ret + 24);
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*ret + 44);
    }*/
    //simple_find(0x7e00 + (1024<<2)*643, disk, 2, "/");
    //return EXIT_SUCCESS;
    /*ret = analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + sizeof(struct ext2_inode)*10);
    if (ret)
    {
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*ret);
        analyze_ext2_dir_entries(disk, 0x7e00 + 1024*(ret) + 12);
    }
    fprintf_light_cyan(stdout, "\nACL Index Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 2*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nACL Data Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 3*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nBoot Loader Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 4*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nUndelete Directory Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 5*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nFirst File Inode -- s_first_ino");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 10*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nSecond File Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 11*sizeof(struct ext2_inode));
    fprintf_light_cyan(stdout, "\nThird File Inode");
    analyze_ext2_inode_table(disk, 0x7e00 + 1024*40 + 12*sizeof(struct ext2_inode));*/

    fclose(disk);

    return EXIT_SUCCESS;
}
