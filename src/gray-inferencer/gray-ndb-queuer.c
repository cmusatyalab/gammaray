/*****************************************************************************
 * gray-ndb-queuer.c                                                         *
 *                                                                           *
 * This file implements a process that pushes asynchronously all writes into *
 * a Redis queue.                                                            *
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
#define _GNU_SOURCE

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitarray.h"
#include "color.h"
#include "deep_inspection.h"
#include "redis_queue.h"
#include "qemu_common.h"
#include "util.h"

int read_loop(int fd, struct kv_store* handle, struct bitarray* bits)
{
    struct timeval start, end;
    uint8_t buf[QEMU_HEADER_SIZE];
    int64_t total = 0, read_ret = 0;
    struct qemu_bdrv_write write;
    size_t len = QEMU_HEADER_SIZE;
    uint64_t counter = 0;

    write.data = (uint8_t*) malloc(4096);

    if (write.data == NULL)
    {
        fprintf_light_red(stderr, "Failed initial alloc for write.data.\n");
        return EXIT_FAILURE;
    }

    while (1)
    {
        gettimeofday(&start, NULL);

        read_ret = read(fd, buf, QEMU_HEADER_SIZE);
        total = read_ret;

        while (read_ret > 0 && total < QEMU_HEADER_SIZE)
        {
            read_ret = read(fd, &buf[total], QEMU_HEADER_SIZE - total);
            total += read_ret;
        }

        /* check for EOF */
        if (read_ret == 0)
        {
            fprintf_light_red(stderr, "Total read: %"PRId64".\n", total);
            fprintf_light_red(stderr, "Reading from stream failed, assuming "
                                      "teardown.\n");
            return EXIT_SUCCESS;
        }

        if (read_ret < 0)
        {
            fprintf_light_red(stderr, "Unknown fatal error occurred, 0 bytes"
                                       "read from stream.\n");
            return EXIT_FAILURE;
        }

        qemu_parse_header(buf, &write);
        len = write.header.nb_sectors * SECTOR_SIZE;
        write.data = (uint8_t*) realloc(write.data, len);

        if (write.data == NULL)
        {
            fprintf_light_red(stderr, "realloc() failed, assuming OOM.\n");
            fprintf_light_red(stderr, "tried allocating: %d bytes\n",
                                      write.header.nb_sectors*SECTOR_SIZE);
            return EXIT_FAILURE;
        }

        read_ret  = read(fd, (uint8_t*) write.data,
                         write.header.nb_sectors*SECTOR_SIZE);
        total = read_ret;

        while (read_ret > 0 && total < write.header.nb_sectors*SECTOR_SIZE)
        {
            read_ret  = read(fd, (uint8_t*) &write.data[total],
                             write.header.nb_sectors*SECTOR_SIZE - total);
            total += read_ret;
        }

        if (read_ret <= 0)
        {
            fprintf_light_red(stderr, "Stream ended while reading sector "
                                      "data.\n");
            return EXIT_FAILURE;
        }

        /* the mountain of things i still regret ! */
        if (redis_async_write_enqueue(handle, bits, write.header.sector_num,
                                  write.data, len))
            fprintf_light_red(stderr, "\tqueue would block: dropping write\n");

        gettimeofday(&end, NULL);
        fprintf(stderr, "[%"PRIu64"]read_loop finished in %"PRIu64
                        " microseconds [%d bytes]\n", counter++,
                        diff_time(start, end),
                        write.header.nb_sectors*SECTOR_SIZE);
    }

    if (write.data)
        free(write.data);

    if (bits)
        bitarray_destroy(bits);

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd;
    char* index, *db, *stream;
    int indexf;
    struct bitarray* bits;

    fprintf_blue(stdout, "gammaray Async Queuer -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    redis_print_version();

    if (argc < 4)
    {
        fprintf_light_red(stderr, "Usage: %s <index file> <stream file>"
                                  " <redis db num>\n", args[0]);
        return EXIT_FAILURE;
    }

    index = args[1];
    stream = args[2];
    db = args[3];

    /* ----------------- hiredis ----------------- */
    struct kv_store* handle = redis_init(db, true);
    if (handle == NULL)
    {
        fprintf_light_red(stderr, "Failed getting Redis context "
                                  "(connection failure?).\n");
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Loading MD filter from: %s\n\n", index);
    indexf = open(index, O_RDONLY | O_NOATIME); 

    if (indexf < 0)
    {
        fprintf_light_red(stderr, "Error opening index file to get MD "
                                  "filter.\n");
        return EXIT_FAILURE;
    }

    if (qemu_load_md_filter(indexf, &bits))
    {
        fprintf_light_red(stderr, "Error getting MD filter from BSON file.\n");
        bits = bitarray_init(5242880);
        bitarray_set_all(bits);
    }

    if (bits == NULL)
    {
        fprintf_light_red(stderr, "Bitarray is NULL!\n");
        return EXIT_FAILURE;
    }

    check_syscall(close(indexf));

    fprintf_cyan(stdout, "Attaching to stream: %s\n\n", stream);

    on_exit((void (*) (int, void *)) redis_shutdown, handle);

    if (strcmp(stream, "-") != 0)
    {
        fd = open(stream, O_RDONLY);
    }
    else
    {
        fd = STDIN_FILENO;
    }
    
    if (fd == -1)
    {
        fprintf_light_red(stderr, "Error opening stream file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    read_loop(fd, handle, bits);
    close(fd);
    return EXIT_SUCCESS;
}
