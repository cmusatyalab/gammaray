#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tail.h"
#include "../disk_analyzer/color.h"
#include "../stream_analyzer/qemu_tracer.h"
#include "../stream_analyzer/deep_inspect.h"

#define SECTOR_SIZE 512

int tail(int fd, char* file)
{
    uint8_t buf[qemu_sizeof_header()];
    int64_t total = 0, read_ret = 0;
    int i;
    struct qemu_bdrv_write write;
    struct tail_conf configuration;
    struct ext2_inode inode;

    /* TODO: generalize book keeping of metadata */
    inode.i_mode = 0x81b4;
    inode.i_uid = 1001;
    inode.i_size = 13;
    inode.i_atime = 1332299058;
    inode.i_ctime = 1332299060;
    inode.i_mtime = 1332299060;
    inode.i_dtime = 0;
    inode.i_gid = 50;
    inode.i_links_count = 1;
    inode.i_blocks = 2;
    inode.i_flags = 0;
    inode.i_osd1 = 1;
    inode.i_block[0] = 9035;
    inode.i_block[1] = 0;
    inode.i_block[2] = 0;
    inode.i_block[3] = 0;
    inode.i_block[4] = 0;
    inode.i_block[5] = 0;
    inode.i_block[6] = 0;
    inode.i_block[7] = 0;
    inode.i_block[8] = 0;
    inode.i_block[9] = 0;
    inode.i_block[10] = 0;
    inode.i_block[11] = 0;
    inode.i_block[12] = 0;
    inode.i_block[13] = 0;
    inode.i_block[14] = 0;
    inode.i_generation = 715258079;
    inode.i_file_acl = 0;
    inode.i_dir_acl = 0;
    inode.i_faddr = 0;
    inode.i_osd2[0] = 0;
    inode.i_osd2[1] = 0;
    inode.i_osd2[2] = 0;
    inode.i_osd2[3] = 0;
    inode.i_osd2[4] = 0;
    inode.i_osd2[5] = 0;
    inode.i_osd2[6] = 0;
    inode.i_osd2[7] = 0;
    inode.i_osd2[8] = 0;
    inode.i_osd2[9] = 0;
    inode.i_osd2[10] = 0;
    inode.i_osd2[11] = 0;

    qemu_init_datastructures();

    /* TODO: generalize, hard-coded configuration */
    configuration.tracked_file = "/mnt/sda1/tce/auth.log";
    configuration.current_file_offset = 1;
    configuration.tracked_inode = inode; /* TODO: fill in inode data */
    configuration.inode_sector = 16529;
    configuration.inode_offset = 128;
    configuration.stream = fd;
    configuration.bst = qemu_get_mapping_bst(configuration.tracked_file); 
    fprintf_light_red(stdout, "config.bst == %p\n", configuration.bst);
    configuration.queue = bst_init(0, NULL);
    configuration.last_sector = ext2_sector_from_block(9035);

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
        write.data = (uint8_t*) calloc(write.header.nb_sectors*SECTOR_SIZE, 1);

        if (write.data == NULL)
        {
            fprintf_light_red(stderr, "calloc() failed, assuming OOM.\n");
            fprintf_light_red(stderr, "tried allocating: %d bytes\n",
                                      write.header.nb_sectors*SECTOR_SIZE);
            return EXIT_FAILURE;
        }

        /* read data */
        read_ret = read(fd, write.data,
                         write.header.nb_sectors*SECTOR_SIZE);
        total = read_ret;

        while (read_ret > 0 && total < write.header.nb_sectors*SECTOR_SIZE)
        {
            read_ret  = read(fd, &(write.data[total]),
                             write.header.nb_sectors*SECTOR_SIZE - total);
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
        tail_parse_block_write(&configuration, write);

        /* TODO: queueing is dangerous---what if two writes to same guy... */
        if (qemu_infer_sector_type(write) == SECTOR_EXT2_DATA)
        {
            if (!qemu_is_tracked(write))
            {
                /* insert mod2 sectors for 1024 block size -- TODO hard code fix */
                for (i = 0; i < write.header.nb_sectors; i += 2)
                {
                    fprintf_cyan(stdout, "enqueueing unknown sector write %"
                                         PRId64"\n",
                                         write.header.sector_num+i);
                    bst_insert(configuration.queue, write.header.sector_num+i,
                               (void*) (write.data+(i*512)));
                }
            }
        }

        //free((void*) write.data); /* TODO: Free elsewhere... */
    }
}

int main(int argc, char* argv[])
{
    int fd;
    char buf[256];
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

    while (1)
    {
        fprintf_light_blue(stdout, "> ");
        fscanf(stdin, "%s", buf);
        
        if (strcmp(buf, "tail") == 0)
        {
            fprintf_cyan(stdout, "Executing tail command.\n");
            tail(fd, "/mnt/sda1/tce/auth.log");
        }

        if (strcmp(buf, "exit") == 0)
        {
            fprintf_cyan(stdout, "Goodbye.\n");
            break;
        }
    }

    close(fd);

    return EXIT_SUCCESS;
}
