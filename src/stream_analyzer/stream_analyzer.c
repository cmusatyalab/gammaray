/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a stream of disk block writes and infere file-level      *
 *          mutations given context from a pre-indexed raw disk image.       *
 *                                                                           *
 *****************************************************************************/

#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../disk_analyzer/color.h"
#include "qemu_tracer.h"
#include "byte_printer.h"
#include "deep_inspect.h"

#define BLOCK_SIZE 128 

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd;
    uint8_t buf[qemu_sizeof_header()];
    int64_t total = 0, read_ret = 0;
    struct qemu_bdrv_write write;
    fprintf_blue(stdout, "Virtual Block Write Stream Analyzer -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: %s <disk index file>\n", args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Loading index: %s\n\n", args[1]);

    if (strcmp(args[1], "-") != 0)
    {
        fd = open(args[1], O_RDONLY);
    }
    else
    {
        fd = 0;
    }
    
    if (fd == -1)
    {
        fprintf_light_red(stderr, "Error opening index file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    while (1)
    {
        read_ret = read(fd, buf, qemu_sizeof_header());
        total = read_ret;

        while (read_ret > 0 && total < qemu_sizeof_header())
        {
            read_ret = read(fd, &buf[total], qemu_sizeof_header() - total);
            total += read_ret;
        }

        /* check for EOF */
        if (read_ret == 0)
        {
            fprintf_light_red(stderr, "Total read: %"PRId64".\n", total);
            fprintf_light_red(stderr, "Reading from stream failed, assuming "
                                      "teardown.\n");
            return EXIT_FAILURE;
        }

        if (read_ret < 0)
        {
            fprintf_light_red(stderr, "Unknown fatal error occurred, 0 bytes"
                                       "read from stream.\n");
            return EXIT_FAILURE;
        }

        qemu_parse_header(buf, &write);
        write.data = (const uint8_t*) malloc(write.header.nb_sectors*512);

        if (write.data == NULL)
        {
            fprintf_light_red(stderr, "malloc() failed, assuming OOM.\n");
            fprintf_light_red(stderr, "tried allocating: %d bytes\n",
                                      write.header.nb_sectors*512);
            return EXIT_FAILURE;
        }

        read_ret  = read(fd, (uint8_t*) write.data,
                         write.header.nb_sectors*512);
        total = read_ret;

        while (read_ret > 0 && total < write.header.nb_sectors*512)
        {
            read_ret  = read(fd, (uint8_t*) &write.data[total],
                             write.header.nb_sectors*512 - total);
            total += read_ret;
        }

        if (read_ret <= 0)
        {
            fprintf_light_red(stderr, "Stream ended while reading sector "
                                       "data.\n");
            return EXIT_FAILURE;
        }

        qemu_print_write(write);
        qemu_print_sector_type(qemu_infer_sector_type(write));
        qemu_deep_inspect(write);
        free((void*) write.data);
    }

    close(fd);

    return EXIT_SUCCESS;
}
