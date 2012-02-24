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

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk;
    struct mbr mbr;
    struct ext2_superblock ext2_superblock;
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
        if (ext2_probe(disk, partition_offset, &ext2_superblock))
        {
            fprintf_light_red(stderr, "ext2 probe failed.\n");
            continue;
        }
        else
        {
            fprintf_light_green(stdout, "--- Analyzing ext2 Partition at "
                                        "Offset 0x%.16"PRIx64" ---\n",
                                        partition_offset);
            ext2_print_superblock(ext2_superblock);
            ext2_list_block_groups(disk, partition_offset, ext2_superblock);
            ext2_list_root_fs(disk, partition_offset, ext2_superblock, "/");
            //ext2_list_files(ext2_superblock);
        }
    }

    /* MBR sector size constant 512 bytes */
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
