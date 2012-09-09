/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Push asynchronously all writes into a Redis queue.               * 
 *                                                                           *
 *****************************************************************************/

#include "color.h"

#include "redis_queue.h"
#include "qemu_common.h"

#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t diff_time(struct timeval start, struct timeval end)
{
    time_t delta_seconds = end.tv_sec - start.tv_sec;
    suseconds_t delta_micro = end.tv_usec - start.tv_usec;
    uint64_t micros = delta_seconds * 1000000 + delta_micro;
    return micros;
}

int read_loop(int fd, struct kv_store* store)
{
    uint8_t buf[QEMU_HEADER_SIZE];
    int64_t total = 0, read_ret = 0;
    struct qemu_bdrv_write write;

    while (1)
    {
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

        write.data = (const uint8_t*)
                     malloc(write.header.nb_sectors*SECTOR_SIZE);

        if (write.data == NULL)
        {
            fprintf_light_red(stderr, "malloc() failed, assuming OOM.\n");
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

        free((void*) write.data);
    }

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd, ret;
    char* db, *stream;
    struct timeval start, end;

    fprintf_blue(stdout, "Async Qemu Queue Pusher -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    redis_print_version();

    if (argc < 5)
    {
        fprintf_light_red(stderr, "Usage: %s <stream file>"
                                  " <redis db num>\n", args[0]);
        return EXIT_FAILURE;
    }

    stream = args[1];
    db = args[2];

    /* ----------------- hiredis ----------------- */
    struct kv_store* handle = redis_init(db, true);
    if (handle == NULL)
    {
        fprintf_light_red(stderr, "Failed getting Redis context "
                                  "(connection failure?).\n");
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Attaching to stream: %s\n\n", stream);

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

    gettimeofday(&start, NULL);
    ret = read_loop(fd, handle);
    gettimeofday(&end, NULL);
    fprintf_light_red(stderr, "read_loop time: %"PRIu64" microseconds\n",
                              diff_time(start, end));
    close(fd);
    redis_flush_pipeline(handle);
    redis_shutdown(handle);

    return EXIT_SUCCESS;
}
