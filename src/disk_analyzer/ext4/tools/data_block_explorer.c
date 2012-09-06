#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbr.h"
#include "ext4.h"

int main(int argc, char* argv[])
{
    FILE* disk;
    struct disk_mbr mbr;
    struct ext4_superblock superblock;
    int64_t partition_offset;
    char buf[SECTOR_SIZE];
    uint64_t block_num;
    uint8_t* block_buf;
    int i;

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

    if (mbr_parse_mbr(disk, &mbr))
    {
        fprintf_light_red(stdout, "Error reading MBR from disk.  Aborting\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(mbr, i)) >= 0)
        {
            if (ext4_probe(disk, partition_offset, &superblock))
            {
                fprintf_light_red(stderr, "ext4 probe failed.\n");
                continue;
            }
            else
            {
                fprintf_light_green(stdout, "--- Found ext4 Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                fprintf(stdout, "Would you like to explore this partition "
                                "[y/n]? ");
                fscanf(stdin, "%c", buf);
                block_buf = (uint8_t*) malloc(ext4_block_size(superblock));

                if (block_buf == NULL)
                {
                    fprintf_light_red(stderr, "Out of Memory error.\n");
                    return EXIT_FAILURE;
                }

                if (buf[0] == 'y' || buf[0] == 'Y')
                {
                    while (1)
                    {
                        fprintf_light_blue(stdout, "> ");
                        fscanf(stdin, "%s", buf);

                        if(strcmp(buf, "show") == 0)
                        {
                            fscanf(stdin, "%"PRIu64, &block_num);
                            fprintf_cyan(stdout, "Examining data block: %"
                                                 PRIu64".\n", block_num);
                            ext4_read_block(disk, partition_offset, superblock,
                                            block_num, block_buf);
                            ext4_print_block(block_buf,
                                             ext4_block_size(superblock));
                        }
                        
                        if (strcmp(buf, "exit") == 0)
                        {
                            fprintf_cyan(stdout, "Goodbye.\n");
                            fclose(disk);
                            return EXIT_SUCCESS; 
                        }
                    }
                }
            }

            free(block_buf);
        }
    }

    fclose(disk);

    return EXIT_SUCCESS;
}
