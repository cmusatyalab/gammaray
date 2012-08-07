#include "probe.h"
#include "util.h"
#include "ext2.h"
#include "ebr.h"

#include "stdlib.h"

int check_partitions(FILE* disk, struct mbr* mbr, int64_t offset)
{
    int i;
    struct ext2_superblock superblock;
    struct mbr ebr;
    int64_t partition_offset;

    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(*mbr, i)) > 0)
        {
            fprintf_light_cyan(stdout, "Probing Partition[%d] offset 0x%.16"PRIx64"\n", i, partition_offset);
            partition_offset += offset;
            fprintf_light_cyan(stdout, "Probing[%d] offset 0x%.16"PRIx64"\n", i, partition_offset);

            if (ext2_probe(disk, partition_offset, &superblock))
            {
                fprintf_light_red(stderr, "ext2 probe failed.\n");
            }
            else
            {
                fprintf_light_green(stdout, "--- Found ext2 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
            }

            if (ebr_probe(disk, partition_offset, &ebr))
            {
                fprintf_light_red(stderr, "ebr probe failed.\n");
            }
            else
            {
               fprintf_light_green(stdout, "--- Found ebr Partition at "
                                           "Offset 0x%.16"PRIx64" ---\n",
                                           partition_offset);
                print_mbr(ebr);
                check_partitions(disk, &ebr, partition_offset);
            }
        }
        else
        {
            fprintf_light_cyan(stdout, "Not probing: unused partition.\n");
        }
    }

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    FILE* disk;
    struct mbr mbr;
    
    fprintf_blue(stdout, "File System Data Block Explorer -- "
                         "By: Wolfgang Richter <wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: %s <raw disk file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing Disk: %s\n\n", argv[1]);

    disk = fopen(argv[1], "r");
    
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
   check_partitions(disk, &mbr, 0);

   fclose(disk);

   return EXIT_SUCCESS;
}
