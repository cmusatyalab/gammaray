/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a stream of disk block writes and infer file-level       * 
 *          mutations given context from a pre-indexed raw disk image.       *
 *                                                                           *
 *****************************************************************************/

#include "color.h"
#include "util.h"

#include "deep_inspection.h"
#include "redis_queue.h"

#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512 

int read_loop(int fd, struct kv_store* store, char* vmname)
{
    uint8_t buf[QEMU_HEADER_SIZE];
    int64_t total = 0, read_ret = 0;
    int sector_type = SECTOR_UNKNOWN;
    uint64_t write_counter = 0;
    struct qemu_bdrv_write write;
    struct ext4_superblock superblock;
    uint8_t* databuf = (uint8_t*) malloc(SECTOR_SIZE * 8);
    write.data = databuf;

    if (qemu_get_superblock(store, &superblock, (uint64_t) 0))
    {
        fprintf_light_red(stderr, "Failed getting superblock.\n");
        return EXIT_FAILURE;
    }

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
            fprintf_light_red(stderr, "Processed: %"PRId64" writes.\n",
                                      write_counter);
            fprintf_light_red(stderr, "Reading from stream failed, assuming "
                                      "teardown.\n");
            free((void*) write.data);
            return EXIT_SUCCESS;
        }

        if (read_ret < 0)
        {
            fprintf_light_red(stderr, "Unknown fatal error occurred, 0 bytes"
                                       "read from stream.\n");
            free((void*) write.data);
            return EXIT_FAILURE;
        }

        qemu_parse_header(buf, &write);
        write.data = (uint8_t*)
                     realloc(write.data, write.header.nb_sectors*SECTOR_SIZE);

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
            free((void*) write.data);
            return EXIT_FAILURE;
        }

        qemu_print_write(&write);
        sector_type = qemu_infer_sector_type(&superblock, &write, store);
        qemu_print_sector_type(sector_type);
        qemu_deep_inspect(&superblock, &write, store, write_counter++, vmname);
    }
    free((void*) write.data);

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd, ret = EXIT_SUCCESS;
    uint64_t time;
    char* index, *db, *stream, *vmname;
    FILE* indexf;
    struct timeval start, end;
    char pretty_micros[32];

    fprintf_blue(stdout, "VM Disk Analysis Engine -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    redis_print_version();

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
    gettimeofday(&start, NULL);
    ret = read_loop(fd, handle, vmname);
    gettimeofday(&end, NULL);

    pretty_print_microseconds(time, pretty_micros, 32);
    fprintf_light_red(stderr, "load_index time: %s.\n", pretty_micros);

    pretty_print_microseconds(diff_time(start, end), pretty_micros, 32);
    fprintf_light_red(stderr, "read_loop time: %s.\n", pretty_micros);

    close(fd);
    redis_flush_pipeline(handle);

    return ret;
}
