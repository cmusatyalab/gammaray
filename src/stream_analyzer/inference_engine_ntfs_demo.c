/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a stream of disk block writes and infere file-level      *
 *          mutations given context from a pre-indexed raw disk image.       *
 *                                                                           *
 *****************************************************************************/

#include "color.h"
#include "deep_inspection.h"
#include "ntfs.h"
#include "util.h"

#include <zmq.h>

#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PUB_SOCKET 13738
#define SECTOR_SIZE 512 
#define OFFSET_OF_INTEREST 3370434560 

void qemu_print_sector_type_ntfs(int type)
{
    switch(type)
    {
        default:
            return;
    };
}

int qemu_infer_sector_type_ntfs(struct qemu_bdrv_write* write)
{
    return 0;
}

int qemu_deep_inspect_ntfs(struct qemu_bdrv_write* write, void* pub_socket,
                           char* vmname, struct ntfs_boot_file* bootf,
                           int64_t partition_offset, uint8_t* original)
{
    uint64_t offset;

    if (write->header.sector_num * SECTOR_SIZE <= OFFSET_OF_INTEREST &&
        write->header.sector_num * SECTOR_SIZE + (write->header.nb_sectors) *
        SECTOR_SIZE >= OFFSET_OF_INTEREST + ntfs_file_record_size(bootf))
    {
        offset = OFFSET_OF_INTEREST - (write->header.sector_num * SECTOR_SIZE);
        fprintf_light_yellow(stdout, "offset of interest in the write: %"PRIu64"\n", OFFSET_OF_INTEREST);
        fprintf_light_green(stdout, "write start sector pos: %"PRIu64"\n", write->header.sector_num * SECTOR_SIZE);
        fprintf_light_blue(stdout, "Checking offset in the write: %"PRIu64"\n", offset);
        fprintf_light_red(stdout, "Potential write to C:/Documents and Settings/wolf/Desktop/demo.txt.txt metadata.\n");
        ntfs_diff_file_record_buffs(original, (uint8_t*) &(write->data[offset]), partition_offset, bootf);
        memcpy(original, &(write->data[offset]), ntfs_file_record_size(bootf));
        hexdump((uint8_t*) &(write->data[offset]), ntfs_file_record_size(bootf));
    }

    return 0;
}

int read_loop(int fd, void* pub_socket, char* vmname,
              struct ntfs_boot_file* bootf, int64_t partition_offset,
              uint8_t* original)
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

        //qemu_print_write(&write);
        qemu_print_sector_type_ntfs(qemu_infer_sector_type_ntfs(&write));
        qemu_deep_inspect_ntfs(&write, pub_socket, vmname, bootf, partition_offset, original);
        free((void*) write.data);
        fflush(stdout);
    }

    return EXIT_SUCCESS;
}


void print_zmq_version()
{
    int major, minor, patch;
    zmq_version (&major, &minor, &patch);
    fprintf(stdout, "Current 0MQ version is %d.%d.%d\n", major, minor, patch);
}

int load_file_record(char* originalfname, uint8_t* original, uint64_t size)
{
    FILE* f = fopen(originalfname, "r");

    if (f)
    {
        if (fread(original, size, 1, f) == 1)
        {
            fclose(f);
            return EXIT_SUCCESS;
        }
    fclose(f);
    }

    return EXIT_FAILURE;
}

int load_bootf(char* bootffname, struct ntfs_boot_file* bootf)
{
    FILE* f = fopen(bootffname, "r");

    if (f)
    {
        if (fread(bootf, sizeof(*bootf), 1, f) == 1)
        {
            fclose(f);
            return EXIT_SUCCESS;
        }
        fclose(f);
    }

    return EXIT_FAILURE;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd, ret;
    char* originalfname, *bootffname, *stream, *vmname;
    int64_t partition_offset;
    struct ntfs_boot_file bootf;
    uint8_t* original;
    fprintf_blue(stdout, "VM Disk Analysis Engine -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    print_zmq_version();

    if (argc < 6)
    {
        fprintf_light_red(stderr, "Usage: %s <original fr> <bootf> "
                                  "<partition offset> <stream file>"
                                  " <vmname>\n", args[0]);
        return EXIT_FAILURE;
    }

    originalfname = args[1];
    bootffname = args[2];
    sscanf(args[3], "%"SCNx64, &partition_offset);
    stream = args[4];
    vmname = args[5];

    fprintf_cyan(stdout, "Using partition offset: 0x%0.16"PRIx64"\n", partition_offset);

    if (load_bootf(bootffname, &bootf))
    {
        fprintf_light_red(stderr, "Error loading boot file [%s].\n", bootffname);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Size of a FILE Record: %"PRIu64"\n",
                         ntfs_file_record_size(&bootf));
    original = (uint8_t*) malloc(ntfs_file_record_size(&bootf));

    if (original == NULL)
    {
        fprintf_light_red(stderr, "Out of Memory error.\n");
        return EXIT_FAILURE;
    }

    if (load_file_record(originalfname, original, ntfs_file_record_size(&bootf)))
    {
        fprintf_light_red(stderr, "Error loading original FILE Record.\n");
        return EXIT_FAILURE;
    }


    /* ----------------- 0MQ ----------------- */
    void* zmq_context = zmq_init(1);
    if (zmq_context == NULL)
    {
        fprintf_light_red(stderr, "Failed getting ZeroMQ context.\n");
        return EXIT_FAILURE;
    }

    void* pub_socket = zmq_socket(zmq_context, ZMQ_PUB);
    if (pub_socket == NULL)
    {
        fprintf_light_red(stderr, "Failed getting PUB socket.\n");
        return EXIT_FAILURE;
    }

    zmq_bind(pub_socket, "tcp://0.0.0.0:13738");
    fprintf_cyan(stdout, "%s: PUB Socket, TCP: %d\n", vmname, PUB_SOCKET);


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

    ret = read_loop(fd, pub_socket, vmname, &bootf, partition_offset, original);
    close(fd);
    zmq_close(pub_socket);
    zmq_term(zmq_context);

    return EXIT_SUCCESS;
}
