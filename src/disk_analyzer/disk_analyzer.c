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
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "bitarray.h"
#include "color.h"
#include "ext2.h"
#include "ext4.h"
#include "ntfs.h"
#include "mbr.h"

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk, *serializef;
    struct disk_mbr mbr;
    struct ext2_superblock ext2_superblock;
    struct ext4_superblock ext4_superblock;
    struct ntfs_boot_file ntfs_bootf;
    struct partition_table_entry pte;
    int64_t partition_offset;
    int32_t i, active_count = 0;
    char buf[4096];
    struct bitarray* bits;
    struct stat fstats;

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
                                  "Does it exist?\n", args[1]);
        return EXIT_FAILURE;
    }

    if (serializef == NULL)
    {
        fclose(disk);
        fprintf_light_red(stderr, "Error opening serialization file '%s'. "
                                  "Does it exist?\n", args[2]);
        return EXIT_FAILURE;
    }

    if (mbr_parse_mbr(disk, &mbr))
    {
        fclose(disk);
        fclose(serializef);
        fprintf_light_red(stderr, "Error reading MBR from disk. Aborting\n");
        return EXIT_FAILURE;
    }

    mbr_print_mbr(mbr);

    if (fstat(fileno(disk), &fstats))
    {
        fclose(disk);
        fclose(serializef);
        fprintf_light_red(stderr, "Error getting fstat info on disk image.\n");
        return EXIT_FAILURE;
    }

    bits = bitarray_init(fstats.st_size / 4096);

    if (bits == NULL)
    {
        fclose(disk);
        fclose(serializef);
        fprintf_light_red(stderr, "Error allocating bitarray.\n");
        return EXIT_FAILURE;
    }

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

    if (mbr_serialize_mbr(mbr, bits, active_count, serializef))
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

                if (mbr_serialize_partition(i, pte, bits, serializef))
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

                if (mbr_serialize_partition(i, pte, bits, serializef))
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
                mbr_get_partition_table_entry(mbr, i, &pte);

                fprintf_light_blue(stdout, "Serializing Partition Data to: "
                                          "%s\n\n", args[2]);

                if (mbr_serialize_partition(i, pte, bits, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "partition table entry.\n");
                    return EXIT_FAILURE;
                }

                if (ext4_serialize_fs(&ext4_superblock, partition_offset, i,
                                      bits,
                                      ext4_last_mount_point(&ext4_superblock),
                                      serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized fs "
                                              "entry.\n");
                    return EXIT_FAILURE;
                }

                if (ext4_serialize_bgds(disk, partition_offset,
                                        &ext4_superblock, bits, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "BGDs\n");
                    return EXIT_FAILURE;
                }

                ext4_serialize_fs_tree(disk, partition_offset, 
                                       &ext4_superblock,
                                       bits,
                                       ext4_last_mount_point(&ext4_superblock),
                                       serializef);
                ext4_serialize_journal(disk, partition_offset, 
                                       &ext4_superblock,
                                       bits,
                                       "journal",
                                       serializef);
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
                if (i == 0) /* HACK: skip boot partition for now... */
                    continue;

                mbr_get_partition_table_entry(mbr, i, &pte);

                fprintf_light_blue(stdout, "Serializing Partition Data to: "
                                          "%s\n\n", args[2]);

                if (mbr_serialize_partition(i, pte, bits, serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "partition table entry.\n");
                    return EXIT_FAILURE;
                }

                if (ntfs_serialize_fs(&ntfs_bootf, bits, partition_offset, i,
                                      "/", serializef))
                {
                    fprintf_light_red(stderr, "Error writing serialized fs "
                                              "entry.\n");
                    return EXIT_FAILURE;
                }

                ntfs_serialize_fs_tree(disk, &ntfs_bootf, bits,
                                       partition_offset, "/", serializef);
            }
        }
    }

    fclose(serializef);
    fclose(disk);

    return EXIT_SUCCESS;
}
