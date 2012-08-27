/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a raw disk image and produce summary datastructures of   *
 *          the partition table, and file system metadata.                   *
 *                                                                           *
 *****************************************************************************/

#define _FILE_OFFSET_BITS 64

#include <inttypes.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "color.h"
#include "ext2.h"
#include "ext4.h"
#include "ntfs.h"
#include "mbr.h"

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk, *serializef;
    struct mbr mbr;
    struct ext2_superblock ext2_superblock;
    struct ext4_superblock ext4_superblock;
    struct ntfs_boot_file ntfs_bootf;
    struct partition_table_entry pte;
    int64_t partition_offset;
    int i, active_count = 0;
    char buf[4096];

    fprintf_blue(stdout, "Raw Disk Analyzer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 3)
    {
        fprintf_light_red(stderr, "Usage: %s <raw disk file> "
                                  "<BSON output file>\n", 
                                  args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing Disk: %s\n\n", args[1]);

    disk = fopen(args[1], "r");

    serializef = fopen(args[2], "w");
    
    setlocale(LC_ALL, "");

    if (disk == NULL)
    {
        fprintf_light_red(stderr, "Error opening raw disk file '%s'. "
                                  "Does it exist?\n", args[2]);
        return EXIT_FAILURE;
    }

    if (serializef == NULL)
    {
        fclose(disk);
        fprintf_light_red(stderr, "Error opening serialization file '%s'. "
                                  "Does it exist?\n", args[2]);
        return EXIT_FAILURE;
    }

    if (parse_mbr(disk, &mbr))
    {
        fclose(disk);
        fclose(serializef);
        fprintf_light_red(stderr, "Error reading MBR from disk. Aborting\n");
        return EXIT_FAILURE;
    }

    print_mbr(mbr);

    memset(buf, 0, sizeof(buf));

    /* active partitions count */
    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(mbr, i)) > 0)
        {
            if (ext2_probe(disk, partition_offset, &ext2_superblock) &&
                ext4_probe(disk, partition_offset, &ext4_superblock) &&
                ntfs_probe(disk, partition_offset, &ntfs_bootf))
            {
                continue;
            }
            else
            {
                active_count++;
            }
        }
    }

    if (mbr_serialize_mbr(mbr, active_count, serializef))
    {
        fprintf_light_red(stderr, "Error serializing MBR.\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(mbr, i)) > 0)
        {
            if (ext2_probe(disk, partition_offset, &ext2_superblock))
            {
                fprintf_light_red(stderr, "ext2 probe failed.\n");
            }
            else
            {
                fprintf(stdout, "\n");
                fprintf_light_green(stdout, "--- Analyzing ext2 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                mbr_get_partition_table_entry(mbr, i, &pte);

                fprintf_light_blue(stdout, "Serializing Partition Data to: "
                                          "%s\n\n", args[2]);

                if (mbr_serialize_partition(i, pte, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "partition table entry.\n");
                    return EXIT_FAILURE;
                }
                
                if (ext2_serialize_fs(&ext2_superblock, 
                                      ext2_last_mount_point(&ext2_superblock),
                                      serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized fs "
                                              "entry.\n");
                    return EXIT_FAILURE;
                }

                if (ext2_serialize_bgds(disk, partition_offset,
                                        &ext2_superblock, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "BGDs\n");
                    return EXIT_FAILURE;
                }

                ext2_serialize_fs_tree(disk, partition_offset, 
                                       &ext2_superblock,
                                       ext2_last_mount_point(&ext2_superblock),
                                       serializef);
            }

            if (ext3_probe(disk, partition_offset, &ext2_superblock))
            {
                fprintf_light_red(stderr, "ext3 probe failed.\n");
            }
            else
            {
                fprintf(stdout, "\n");
                fprintf_light_green(stdout, "--- Analyzing ext3 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                mbr_get_partition_table_entry(mbr, i, &pte);

                fprintf_light_blue(stdout, "Serializing Partition Data to: "
                                          "%s\n\n", args[2]);

                if (mbr_serialize_partition(i, pte, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "partition table entry.\n");
                    return EXIT_FAILURE;
                }
                
                if (ext2_serialize_fs(&ext2_superblock, 
                                      ext2_last_mount_point(&ext2_superblock),
                                      serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized fs "
                                              "entry.\n");
                    return EXIT_FAILURE;
                }

                if (ext2_serialize_bgds(disk, partition_offset,
                                        &ext2_superblock, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "BGDs\n");
                    return EXIT_FAILURE;
                }

                ext2_serialize_fs_tree(disk, partition_offset, 
                                       &ext2_superblock,
                                       ext2_last_mount_point(&ext2_superblock),
                                       serializef);
            }

            if (ext4_probe(disk, partition_offset, &ext4_superblock))
            {
                fprintf_light_red(stderr, "ext4 probe failed.\n");
            }
            else
            {
                fprintf(stdout, "\n");
                fprintf_light_green(stdout, "--- Analyzing ext4 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                //ext4_print_superblock(ext4_superblock);
                //ext4_print_features(&ext4_superblock);
                //ext4_list_block_groups(disk, partition_offset,
                //                       ext4_superblock);
                //ext4_list_root_fs(disk, partition_offset, ext4_superblock,
                //                  ext4_last_mount_point(&ext4_superblock));
                ext4_reconstruct_root_fs(disk, partition_offset,
                                         ext4_superblock,
                                         ext4_last_mount_point(
                                             &ext4_superblock),
                                         "/tmp/ext4_copy/");
            }

            if (ntfs_probe(disk, partition_offset, &ntfs_bootf))
            {
                fprintf_light_red(stderr, "NTFS probe failed.\n");
            }
            else
            {
                fprintf(stdout, "\n");
                fprintf_light_green(stdout, "--- Analyzing NTFS Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                ntfs_print_boot_file(&ntfs_bootf, partition_offset);
                //ntfs_diff_file_records(disk, 0, 1, partition_offset,& ntfs_bootf);
                ntfs_walk_mft(disk, &ntfs_bootf, partition_offset);
            }
        }
    }

    fclose(serializef);
    fclose(disk);

    return EXIT_SUCCESS;
}
