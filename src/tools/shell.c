#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tail.h"
#include "../disk_analyzer/color.h"
#include "../stream_analyzer/qemu_tracer.h"

#define SECTOR_SIZE 512

int main(int argc, char* argv[])
{
    int fd;
    uint8_t buf[qemu_sizeof_header()];
    int64_t total = 0, read_ret = 0;
    struct qemu_bdrv_write write;
    struct tail_conf configuration;
    struct ext2_inode inode;

    fprintf_blue(stdout, "Virtual Disk Block Write Stream Shell -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: ./%s <stream>\n", argv[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Following stream: %s\n\n", argv[1]);

    if (strcmp(argv[1], "-") != 0)
    {
        fd = open(argv[1], O_RDONLY);
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

    /* TODO: generalize, hard-coded configuration */
    configuration.tracked_file = "/mnt/sda1/tce/auth.log";
    configuration.current_file_offset = 0;
    configuration.tracked_inode = inode; /* TODO: fill in inode data */
    configuration.inode_sector = 0;
    configuration.inode_offset = 0;

    while (1)
    {
        /* read a full header worth of bytes for our analysis */
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

        /* parse the header and allocate memory for data */
        qemu_parse_header(buf, &write);
        write.data = (const uint8_t*) malloc(write.header.nb_sectors*SECTOR_SIZE);

        if (write.data == NULL)
        {
            fprintf_light_red(stderr, "malloc() failed, assuming OOM.\n");
            fprintf_light_red(stderr, "tried allocating: %d bytes\n",
                                      write.header.nb_sectors*SECTOR_SIZE);
            return EXIT_FAILURE;
        }

        /* read data */
        read_ret = read(fd, (uint8_t*) write.data,
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

        tail_parse_block_write(&configuration, write);

        free((void*) write.data);
    }

    close(fd);

    return EXIT_SUCCESS;
}
