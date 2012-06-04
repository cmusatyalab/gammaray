#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbr.h"
#include "ntfs.h"

int main(int argc, char* argv[])
{
    FILE* disk;
    struct mbr mbr;
    struct ntfs_boot_file bootf;
    int64_t partition_offset;
    char buf[SECTOR_SIZE];
    uint64_t recorda, recordb;
    uint8_t* bufa = NULL, *bufb = NULL;
    int i;

    fprintf_blue(stdout, "FILE Record NTFS Explorer -- "
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

    for (i = 0; i < 4; i++)
    {
        if ((partition_offset = mbr_partition_offset(mbr, i)) >= 0)
        {
            if (ntfs_probe(disk, partition_offset, &bootf))
            {
                fprintf_light_red(stderr, "NTFS probe failed.\n");
                continue;
            }
            else
            {
                fprintf_light_green(stdout, "--- Found NTFS Partition at "
                                            "Offset 0x%.16"PRIx64" ---\n",
                                            partition_offset);
                fprintf(stdout, "Would you like to explore this partition "
                                "[y/n]? ");
                fscanf(stdin, "%s", buf);

                if (buf[0] == 'y' || buf[0] == 'Y')
                {
                    bufa = (uint8_t*) malloc(ntfs_file_record_size(&bootf));
                    bufb = (uint8_t*) malloc(ntfs_file_record_size(&bootf));

                    if (bufa == NULL || bufb == NULL)
                    {
                        fprintf_light_red(stderr, "Out of Memory error.\n");
                        return EXIT_FAILURE;
                    }

                    while (1)
                    {
                        fprintf_light_blue(stdout, "> ");
                        fscanf(stdin, "%s", buf);

                        if(strcmp(buf, "diff") == 0)
                        {
                            fscanf(stdin, "%"PRIu64, &recorda);
                            fscanf(stdin, "%"PRIu64, &recordb);
                            fprintf_cyan(stdout, "Examining FILE Records: %"PRIu64
                                                 " and %"PRIu64".\n", recorda, recordb);
                            ntfs_diff_file_records(disk, recorda, recordb, partition_offset, &bootf);
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

            if (bufa)
                free(bufa);
            if (bufb)
            free(bufb);
        }
    }

    fclose(disk);

    return EXIT_SUCCESS;
}
