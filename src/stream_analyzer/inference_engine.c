/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a stream of disk block writes and infer file-level       * 
 *          mutations given context from a pre-indexed raw disk image.       *
 *                                                                           *
 *****************************************************************************/

#include "color.h"
#include "deep_inspection.h"

#include "redis_queue.h"

#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512 

int read_loop(int fd, struct mbr* mbr, struct kv_store* store, char* vmname,
              uint64_t block_size)
{
    uint8_t buf[QEMU_HEADER_SIZE];
    int64_t total = 0, read_ret = 0;
    int sector_type = SECTOR_UNKNOWN;
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

        qemu_parse_header(buf, &write);
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

        qemu_print_write(&write);
        sector_type = qemu_infer_sector_type(&write, store, block_size);
        qemu_print_sector_type(sector_type);
        if (sector_type == SECTOR_EXT2_INODE ||
            sector_type == SECTOR_EXT2_DATA)
            qemu_deep_inspect(&write, store, vmname, block_size);
        free((void*) write.data);
        fflush(stdout);
    }

    return EXIT_SUCCESS;
}

void print_hiredis_version()
{
    fprintf(stdout, "Current libhiredis version is %d.%d.%d\n", HIREDIS_MAJOR,
                                                                HIREDIS_MINOR,
                                                                HIREDIS_PATCH);
}

uint64_t diff_time(struct timeval start, struct timeval end)
{
    time_t delta_seconds = end.tv_sec - start.tv_sec;
    suseconds_t delta_micro = end.tv_usec - start.tv_usec;
    uint64_t micros = delta_seconds * 1000000 + delta_micro;
    return micros;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd, ret;
    uint64_t block_size, load_time;
    char* index, *db, *stream, *vmname;
    struct mbr mbr;
    FILE* indexf;
    struct timeval start, end;

    fprintf_blue(stdout, "VM Disk Analysis Engine -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    print_hiredis_version();

    if (argc < 5)
    {
        fprintf_light_red(stderr, "Usage: %s <disk index file> <stream file>"
                                  " <redis db num> <vmname>\n", args[0]);
        return EXIT_FAILURE;
    }

    index = args[1];
    stream = args[2];
    db = args[3];
    vmname = args[4];

    fprintf_cyan(stdout, "%s: loading index: %s\n\n", vmname, index);

    indexf = fopen(index, "r");

    if (indexf == NULL)
    {
        fprintf_light_red(stderr, "Error opening index file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    /* ----------------- hiredis ----------------- */
    struct kv_store* handle = redis_init(db);
    if (handle == NULL)
    {
        fprintf_light_red(stderr, "Failed getting Redis context "
                                  "(connection failure?).\n");
        return EXIT_FAILURE;
    }

    gettimeofday(&start, NULL);
    if (qemu_load_index(indexf, &mbr, handle))
    {
        fprintf_light_red(stderr, "Error deserializing index.\n");
        return EXIT_FAILURE;
    }
    gettimeofday(&end, NULL);

    load_time = diff_time(start, end);

    fprintf_cyan(stdout, "%s: attaching to stream: %s\n\n", vmname, stream);

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

    fclose(indexf);
    block_size = qemu_get_block_size(handle, 0);
    gettimeofday(&start, NULL);
    ret = read_loop(fd, &mbr, handle, vmname, block_size);
    gettimeofday(&end, NULL);
    fprintf_light_red(stderr, "load_index time: %"PRIu64" microseconds\n",
                              load_time);
    fprintf_light_red(stderr, "read_loop time: %"PRIu64" microseconds\n",
                              diff_time(start, end));
    close(fd);
    redis_flush_pipeline(handle);
    exit(0);
    redis_shutdown(handle);

    return EXIT_SUCCESS;
}
