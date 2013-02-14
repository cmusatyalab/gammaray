#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbr.h"
#include "ntfs.h"

void save_bootf(char* fname, struct ntfs_boot_file* bootf)
{
    FILE* f = fopen(fname, "w");

    if (f)
    {
        fwrite(bootf, sizeof(*bootf), 1, f);
        fclose(f);
    }
}

void save_file_record(char* fname, uint8_t* record, uint64_t size)
{
    FILE* f = fopen(fname, "w");

    if (f)
    {
        fwrite(record, size, 1, f);
        fclose(f);
    }
}

int main(int argc, char* argv[])
{
    FILE* disk;
    struct disk_mbr mbr;
    struct ntfs_boot_file bootf;
    int64_t partition_offset;
    char buf[SECTOR_SIZE], bootffname[4096], filename[4096];
    uint64_t recorda, recordb;
    uint8_t* buf_record = NULL;
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

    if (mbr_parse_mbr(disk, &mbr))
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
                    buf_record = (uint8_t*) malloc(ntfs_file_record_size(&bootf));

                    if (buf == NULL)
                    {
                        fprintf_light_red(stderr, "Out of Memory error.\n");
                        return EXIT_FAILURE;
                    }

                    while (1)
                    {
                        fprintf_light_blue(stdout, "> ");
                        fscanf(stdin, "%s", buf);

                        if (strcmp(buf, "savebootf") == 0)
                        {
                            fscanf(stdin, "%s", bootffname);
                            fprintf_light_cyan(stdout, "Saving bootf to file '%s'\n", bootffname);
                            save_bootf(bootffname, &bootf);
                        }

                        if (strcmp(buf, "savefr") == 0)
                        {

                            fscanf(stdin, "%"PRIu64, &recorda);
                            fscanf(stdin, "%s", filename);
                            fprintf_light_cyan(stdout, "Saving FILE record [%"PRId64"] to file '%s'\n", recorda, filename);
                            ntfs_read_file_record(disk, recorda, partition_offset, &bootf, buf_record, NULL);
                            save_file_record(filename, buf_record, ntfs_file_record_size(&bootf));
                        }

                        if (strcmp(buf, "diff") == 0)
                        {
                            fscanf(stdin, "%"PRIu64, &recorda);
                            fscanf(stdin, "%"PRIu64, &recordb);
                            fprintf_cyan(stdout, "Examining FILE Records: %"PRIu64
                                                 " and %"PRIu64".\n", recorda, recordb);
                            ntfs_diff_file_records(disk, recorda, recordb, partition_offset, &bootf);
                        }
                        
                        if (strcmp(buf, "exit") == 0 || strcmp(buf, "quit") == 0)
                        {
                            fprintf_cyan(stdout, "Goodbye.\n");
                            fclose(disk);
                            return EXIT_SUCCESS; 
                        }
                    }
                }
            }

            if (buf_record)
                free(buf_record);
        }
    }

    fclose(disk);

    return EXIT_SUCCESS;
}
