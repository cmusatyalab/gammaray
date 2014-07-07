/*****************************************************************************
 * gray-crawler.c                                                            *
 *                                                                           *
 * Analyze a raw disk image and produce summary datastructures of            *
 * the partition table, and file system metadata.                            *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013-2014 Carnegie Mellon University                          *
 *                                                                           *
 *   Licensed under the Apache License, Version 2.0 (the "License");         *
 *   you may not use this file except in compliance with the License.        *
 *   You may obtain a copy of the License at                                 *
 *                                                                           *
 *       http://www.apache.org/licenses/LICENSE-2.0                          *
 *                                                                           *
 *   Unless required by applicable law or agreed to in writing, software     *
 *   distributed under the License is distributed on an "AS IS" BASIS,       *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
 *   See the License for the specific language governing permissions and     *
 *   limitations under the License.                                          *
 *****************************************************************************/

#include <stdint.h>
#include <stdlib.h>

#include "color.h"
#include "ext4.h"
#include "gray-crawler.h"
#include "mbr.h"

/* supported file system serializers */
struct gray_fs_crawler crawlers[] = {
    GRAY_FS(ext4),
    //GRAY_FS(ntfs), TODO
    //GRAY_FS(fat32), TODO
    {NULL, NULL, NULL, NULL} /* guard value */
};

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* disk, *serializef;
    struct gray_fs_crawler* crawler;
    struct fs partition_entry;
    struct disk_mbr mbr;
    int i;

    fprintf_blue(stdout, "Raw Disk Crawler -- By: Wolfgang Richter "
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

    /* pull MBR info */
    if (mbr_parse_mbr(disk, &mbr))
    {
        fclose(disk);
        fclose(serializef);
        fprintf_light_red(stderr, "Error reading MBR from disk. Aborting\n");
        return EXIT_FAILURE;
    }

    mbr_print_mbr(mbr);

    for (i = 0; i < 4; i++) {
        partition_entry = (struct fs) {i, 0, NULL, NULL, NULL};

        partition_entry.pt_off = mbr_partition_offset(mbr, i);

        if (partition_entry.pt_off > 0)
        {
            crawler = crawlers;

            while (crawler->fs_name) {

                fprintf_white(stdout, "\nProbing for %s... ",
                                      crawler->fs_name);
                
                if (crawler->probe(disk, &partition_entry))
                {
                    fprintf_white(stdout, "Not found.\n");
                }
                else
                {
                    fprintf_light_white(stdout, "found %s file system!\n",
                                                 crawler->fs_name);

                    if (crawler->serialize(disk, &partition_entry, serializef))
                    {
                        fprintf_light_red(stderr, "Error serializing "
                                                  "partition.\n");
                        return EXIT_FAILURE;
                    }
                }

                crawler->cleanup(&partition_entry);
                
                crawler++;
            }
        }
    }

    return EXIT_SUCCESS;
}
