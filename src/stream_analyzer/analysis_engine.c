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

#include "color.h"
#include "deep_inspection.h"

#define SECTOR_SIZE 512 

int read_loop(int fd, struct mbr* mbr)
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

        //qemu_init_datastructures();
        //qemu_print_write(write);
        //qemu_print_sector_type(qemu_infer_sector_type(write));
        //qemu_deep_inspect(write);
        //free((void*) write.data);
    }

    return EXIT_SUCCESS;
}


/* main thread of execution */
int main(int argc, char* args[])
{
    int fd, ret;
    char* index, *stream;
    struct mbr mbr;
    FILE* indexf;
    fprintf_blue(stdout, "VM Disk Analysis Engine -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 3)
    {
        fprintf_light_red(stderr, "Usage: %s <disk index file> <stream file>"
                                  "\n", args[0]);
        return EXIT_FAILURE;
    }

    index = args[1];
    stream = args[2];

    fprintf_cyan(stdout, "Loading index: %s\n\n", index);

    indexf = fopen(index, "r");

    if (indexf == NULL)
    {
        fprintf_light_red(stderr, "Error opening index file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    if (qemu_load_index(indexf, &mbr))
    {
        fprintf_light_red(stderr, "Error deserializing index.\n");
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

    ret = read_loop(fd, &mbr);
    close(fd);
    fclose(indexf);

    return EXIT_SUCCESS;
}
