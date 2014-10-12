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
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "color.h"
#include "ext4.h"
#include "gray-crawler.h"
#include "mbr.h"
#include "ntfs.h"
#include "util.h"

/* support multiple partition table types */
struct gray_fs_pt_crawler pt_crawlers[] = {
    //GRAY_FS_GPT(gpt), TODO
    GRAY_PT(mbr),
    {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL} /* guard value */
};

/* supported file system serializers */
struct gray_fs_crawler crawlers[] = {
    GRAY_FS(ext4),
    GRAY_FS(ntfs),
    //GRAY_FS(fat32), TODO
    {NULL, NULL, NULL, NULL} /* guard value */
};

/* utility function */
void cleanup(int disk, int serializef, struct bitarray* bits)
{
    if (disk)
        check_syscall(close(disk));

    if (serializef)
        check_syscall(close(serializef)); 

    if (bits)
        bitarray_destroy(bits);
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int disk, serializef;
    struct gray_fs_pt_crawler* pt_crawler;
    struct gray_fs_crawler* crawler;
    struct bitarray* bits = NULL;
    struct stat fstats;
    struct pt ptdata;
    struct pte ptedata;
    struct fs fsdata;
    bool present;

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

    disk = open(args[1], DISK_FLAGS);

    if (disk < 0)
    {
        fprintf_light_red(stderr, "Error opening raw disk file '%s'. ",
                                  "Does it exist?\n", args[1]);
        return EXIT_FAILURE;
    }

    serializef = open(args[2], SERIALIZEF_FLAGS, SERIALIZEF_MODE);

    if (serializef < 0)
    {
        cleanup(disk, serializef, bits);
        fprintf_light_red(stderr, "Error opening serialization file '%s'. "
                                  "Does it exist?\n", args[2]);
        return EXIT_FAILURE;
    }

    /* pull MBR/partition table info */
    pt_crawler = pt_crawlers;
    present = false;

    while (pt_crawler->pt_name && !present)
    {

        fprintf_white(stdout, "\nProbing for %s... ",
                              pt_crawler->pt_name);

        fseek(disk, SEEK_SET, 0);
        if (pt_crawler->probe(disk, &ptdata))
        {

            fprintf_white(stdout, "not found.\n");
        }
        else
        {
            pt_crawler->print(ptdata);
            present = true;
            fprintf_light_white(stdout, "found %s partition table!\n",
                                        pt_crawler->pt_name);
            break;
        }

        pt_crawler++;
    }
    
    if (!present)
    {
        cleanup(disk, serializef, bits);
        fprintf_light_red(stderr, "Error reading PT from disk. Aborting.\n");
        return EXIT_FAILURE;
    }

    if (check_syscall(fstat(disk, &fstats)))
    {
        cleanup(disk, serializef, bits);
        fprintf_light_red(stderr, "Error getting fstat info on disk image.\n");
        return EXIT_FAILURE;
    }

    bits = bitarray_init(fstats.st_size / 4096);

    if (bits == NULL)
    {
        cleanup(disk, serializef, bits);
        fprintf_light_red(stderr, "Error allocating bitarray.\n");
        return EXIT_FAILURE;
    }

    if (pt_crawler->serialize_pt(ptdata, bits, serializef))
    {
        cleanup(disk, serializef, bits);
        fprintf_light_red(stderr, "Error serializing PT.\n");
        return EXIT_FAILURE;
    }

    while (pt_crawler->get_next_partition(ptdata, &ptedata))
    {
        fsdata = (struct fs) {0, 0, NULL, NULL, NULL};

        fsdata.pte = ptedata.pt_num;
        fsdata.pt_off = ptedata.pt_off;
        fsdata.bits = bits;

        if (fsdata.pt_off > 0)
        {
            crawler = crawlers;
            present = false;

            while (crawler->fs_name && !present) {

                fprintf_white(stdout, "\nProbing for %s... ",
                                      crawler->fs_name);
                
                if (crawler->probe(disk, &fsdata))
                {
                    fprintf_white(stdout, "not found.\n");
                }
                else
                {
                    fprintf_light_white(stdout, "found %s file system!\n",
                                                 crawler->fs_name);

                    present = true;

                    if (pt_crawler->serialize_pte(ptedata, serializef))
                    {
                        pt_crawler->cleanup_pte(ptedata);
                        crawler->cleanup(&fsdata);
                        cleanup(disk, serializef, bits);
                        fprintf_light_red(stderr, "Error serializing "
                                                  "partition entry.\n");
                        return EXIT_FAILURE;
                    }
                    
                    if (crawler->serialize(disk, &fsdata, serializef))
                    {
                        pt_crawler->cleanup_pte(ptedata);
                        crawler->cleanup(&fsdata);
                        cleanup(disk, serializef, bits);
                        fprintf_light_red(stderr, "Error serializing "
                                                  "file system.\n");
                        return EXIT_FAILURE;
                    }
                }

                pt_crawler->cleanup_pte(ptedata);
                crawler->cleanup(&fsdata);
                
                crawler++;
            }
        }
    }

    bitarray_serialize(bits, serializef);
    pt_crawler->cleanup_pt(ptdata);
    cleanup(disk, serializef, bits);
    return EXIT_SUCCESS;
}
