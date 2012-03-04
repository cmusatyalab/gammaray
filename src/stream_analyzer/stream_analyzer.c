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

#define BLOCK_SIZE 128 

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd;
    uint8_t buf[BLOCK_SIZE + 1], buf2[BLOCK_SIZE + 1];
    uint8_t* read_buf = buf;
    int64_t total = 0, parsed = 0, total_parsed = 0, position = 0, offset = 0;
    struct qemu_bdrv_co_io_em write;
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
        fprintf_light_cyan(stderr, "debug: looping to read...\n");
        total = read(fd, &read_buf[offset], BLOCK_SIZE - 1 - offset);
        fprintf_light_cyan(stderr, "debug: got %d bytes\n", total);
        print_bytes((char*) read_buf, total+offset);

        /* check for EOF */
        if (total == 0)
        {
            fprintf_light_red(stderr, "Total read: %"PRId64".\n", total);
            fprintf_light_red(stderr, "Reading from stream failed, assuming "
                                      "teardown.\n");
            break;
        }

        if (total < 0)
        {
            fprintf_light_red(stderr, "Unknown fatal error occurred, 0 bytes"
                                       "read from stream.\n");
            return EXIT_FAILURE;
        }

        total += offset;
        read_buf[total] = 0; /* make sure final guard byte is 0 for string */
        position = 0;

        write.write = 0;

        while (position >= 0 && position < total)
        {
            parsed = parse_write(&read_buf[position], total-position, &write);
            if (parsed > 0)
            {
                position += parsed;
                total_parsed += parsed;
            }
            else if (parsed == -1)
            {
                offset = strlen((char*) &read_buf[position]);
                fprintf_light_red(stderr, "Split buffer, copying end to "
                                          "beginning: \'%s\'.\n",
                                          &read_buf[position]);
                /* want current pos to end of buf copied to straddle_buf beginning */
                /* then want to read into straddle buf from offset */
                if (read_buf == buf)
                {
                    read_buf = buf2;
                    memcpy(read_buf, &buf[position], offset+1);
                    fprintf_light_red(stderr, "Split buffer, copyied end to "
                                              "beginning: \'%s\'.\n",
                                              read_buf);
                }
                else if (read_buf == buf2)
                {
                    read_buf = buf;
                    memcpy(read_buf, &buf2[position], offset+1);
                    fprintf_light_red(stderr, "Split buffer, copyied end to "
                                              "beginning: \'%s\'.\n",
                                              read_buf);
                }
                else
                {
                    fprintf_light_red(stderr, "Fatal error, read_buf is invalid pointer.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            }

            if (write.write == 1)
            {
                qemu_print_write(write);
                qemu_print_sector_type(qemu_infer_sector_type(write));
            }

            offset = 0;
        }
    }

    close(fd);

    return EXIT_SUCCESS;
}
