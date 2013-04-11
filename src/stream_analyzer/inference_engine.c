/*****************************************************************************
 * inference_engine.c                                                        *
 *                                                                           *
 * This file implements a process that analyzes a stream of disk block writes*
 * and infer file-level mutations given context from a pre-indexed raw disk  *
 * image.                                                                    *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013 Carnegie Mellon University                               *
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
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "color.h"
#include "util.h"
#include "deep_inspection.h"
#include "redis_queue.h"

#define SECTOR_SIZE 512 

int read_loop(struct kv_store* store, char* vmname, FILE* index)
{
    struct timeval start, end;
    uint64_t write_counter = 0, partition_offset, time = 0;
    struct qemu_bdrv_write write;
    struct super_info super_info;
    char pretty_time[32];
    
    if (qemu_get_superinfo(store, &super_info, (uint64_t) 0))
    {
        fprintf_light_red(stderr, "Failed getting superblock.\n");
        return EXIT_FAILURE;
    }

    if (qemu_get_pt_offset(store, &partition_offset, (uint64_t) 0))
    {
        fprintf_light_red(stderr, "Failed getting partition offset.\n");
        return EXIT_FAILURE;
    }

    while (1)
    {
        write.data = NULL;

        if (redis_async_write_dequeue(store, &write))
        {
            fprintf_light_red(stderr, "Redis dequeue failure.\n"
                                      "Shutting down\n");
            if (write.data)
                free(write.data);
            return EXIT_SUCCESS;
        }

        qemu_print_write(&write);
        gettimeofday(&start, NULL);
        qemu_deep_inspect(&super_info, &write, store, write_counter++, vmname,
                          partition_offset, index);
        gettimeofday(&end, NULL);
        time = diff_time(start, end);
        pretty_print_microseconds(time, pretty_time, 32);
        fprintf_cyan(stdout, "[%"PRIu64"] write inference in %s.\n",
                             write_counter, pretty_time);
        if (write.data)
            free(write.data);
    }

    fprintf(stdout, "Processed: %"PRIu64" writes.\n", write_counter);

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int ret = EXIT_SUCCESS;
    uint64_t time;
    char* index, *db, *vmname;
    FILE* indexf;
    struct timeval start, end;
    char pretty_micros[32];

    fprintf_blue(stdout, "VM Disk Analysis Engine -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    redis_print_version();

    if (argc < 4)
    {
        fprintf_light_red(stderr, "Usage: %s <disk index file> " 
                                  " <redis db num> <vmname>\n", args[0]);
        return EXIT_FAILURE;
    }

    index = args[1];
    db = args[2];
    vmname = args[3];

    fprintf_cyan(stdout, "%s: loading index: %s\n\n", vmname, index);

    indexf = fopen(index, "r");

    if (indexf == NULL)
    {
        fprintf_light_red(stderr, "Error opening index file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    /* ----------------- hiredis ----------------- */
    struct kv_store* handle = redis_init(db, false);
    if (handle == NULL)
    {
        fprintf_light_red(stderr, "Failed getting Redis context "
                                  "(connection failure?).\n");
        return EXIT_FAILURE;
    }
    
    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    gettimeofday(&start, NULL);
    if (qemu_load_index(indexf, handle))
    {
        fprintf_light_red(stderr, "Error deserializing index.\n");
        return EXIT_FAILURE;
    }
    gettimeofday(&end, NULL);
    time = diff_time(start, end);

    redis_flush_pipeline(handle);

    gettimeofday(&start, NULL);
    ret = read_loop(handle, vmname, indexf);
    gettimeofday(&end, NULL);

    fclose(indexf);
    pretty_print_microseconds(time, pretty_micros, 32);
    fprintf_light_red(stderr, "load_index time: %s.\n", pretty_micros);

    pretty_print_microseconds(diff_time(start, end), pretty_micros, 32);
    fprintf_light_red(stderr, "read_loop time: %s.\n", pretty_micros);

    redis_flush_pipeline(handle);

    return ret;
}
