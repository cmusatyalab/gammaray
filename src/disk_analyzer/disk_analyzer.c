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
#include <string.h>

#include "color.h"
#include "ext2.h"
#include "mbr.h"

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk;
    struct mbr mbr;
    struct ext2_superblock ext2_superblock;
    struct partition_table_entry pte;
    int64_t partition_offset;
    int i;
    char buf[4096];
    char* vm_name = NULL;

    fprintf_blue(stdout, "Raw Disk Analyzer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 3)
    {
        fprintf_light_red(stderr, "Usage: %s <raw disk file> <VM name>\n", 
                                  args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing Disk: %s\n\n", args[1]);

    disk = fopen(args[1], "r");

    vm_name = args[2];
    
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

    memset(buf, 0, sizeof(buf));

    print_mbr(mbr);
    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(mbr, i)) >= 0)
        {
            if (ext2_probe(disk, partition_offset, &ext2_superblock))
            {
                fprintf_light_red(stderr, "ext2 probe failed.\n");
                continue;
            }
            else
            {
                fprintf(stdout, "\n");
                fprintf_light_green(stdout, "--- Analyzing ext2 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                mbr_get_partition_table_entry(mbr, i, &pte);
                mbr_print_numbers(mbr);

                snprintf(buf, 4096, "/tmp/%s.%d.pte", vm_name, i);
                fprintf_light_red(stdout, "Serializing Partition Data to: "
                                          "%s\n", buf);
                if (mbr_serialize_partition(i, pte, buf))
                {
                    fprintf_light_red(stderr, "Error writing serialized "
                                              "partition table entry.\n");
                    return EXIT_FAILURE;
                }
                print_partition_sectors(pte);
                //ext2_print_sectormap(disk, partition_offset, ext2_superblock);
                //ext2_print_superblock(ext2_superblock);
                ext2_list_block_groups(disk, partition_offset, ext2_superblock);
                ext2_list_root_fs(disk, partition_offset, ext2_superblock, "/mnt/sda1/");
                //ext2_reconstruct_root_fs(disk, partition_offset, ext2_superblock,
                //                         "", "/home/wolf/copydisk/");
            }
        }
    }

    fclose(disk);

    return EXIT_SUCCESS;
}
