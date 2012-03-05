#include "qemu_tracer.h"
#include "../disk_analyzer/color.h"
#include "tokenizer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int64_t qemu_sizeof_binary_header()
{
    return QEMU_BINARY_HEADER_SIZE;
}

int qemu_print_write(struct qemu_bdrv_co_io_em write)
{
    fprintf_light_blue(stdout, "brdv_co_io_em event\n");
    fprintf_yellow(stdout, "\tbs: 0x%0.x\n", write.bs);
    fprintf_yellow(stdout, "\tsector: %"PRId64"\n", write.sector);
    fprintf_yellow(stdout, "\tsector_count: %"PRIu32"\n", write.sector_count);
    fprintf_yellow(stdout, "\twrite: %"PRIu8"\n", write.write);
    fprintf_yellow(stdout, "\tacb: 0x%"PRIx32"\n", write.acb);
    return 0;
}

int qemu_print_binary_write(struct qemu_bdrv_write write)
{
    fprintf_light_blue(stdout, "brdv_write event\n");
    fprintf_yellow(stdout, "\tsector_num: %0."PRId64"\n", write.sector_num);
    fprintf_yellow(stdout, "\tnb_sectors: %d\n", write.nb_sectors);
    fprintf_yellow(stdout, "\tdata: %p\n", write.data);
    return 0;
}

int64_t qemu_parse_binary_header(uint8_t* event_stream,
                                 struct qemu_bdrv_write* write)
{
    write->sector_num = *((int64_t*) event_stream);
    write->nb_sectors = *((int*) (event_stream + sizeof(int64_t)));
    return 0;
}

/* This function parses a single line of input.
 * It returns either the number of characters consumed,
 * or a -1 to signify a full line could not be parsed or
 * an incomplete message was encountered.
 *
 * Incomplete messages should not occur, but if a line can not
 * be read, this means more bytes are needed from the stream
 * for further processing. */
int64_t parse_write(uint8_t* event_stream, int64_t stream_size, struct qemu_bdrv_co_io_em* write)
{
    char* line, *tokens[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                             NULL, NULL, NULL};
    int64_t parsing;

    line = tokenize_line((char*) event_stream, stream_size);
    if (line == NULL) /* backup to process a full line at a time */
        return -1;

    parsing = strlen(line);
    fprintf_yellow(stderr, "debug: operating on string '%s'\n", line);
    tokenize_space_split((char *) event_stream, tokens, 11, parsing);

    if (strcmp(tokens[0], BDRV_CO_IO_EM) == 0)
    {
        if (tokens[2] == NULL)
        {
            tokenize_space_unsplit(line, parsing);
            return -1;
        }
        sscanf(tokens[2], "%"PRIx32, &(write->bs));
        
        if (tokens[4] == NULL)
        {
            tokenize_space_unsplit(line, parsing);
            return -1;
        }
        sscanf(tokens[4], "%"PRId64, &(write->sector));
        
        if (tokens[6] == NULL)
        {
            tokenize_space_unsplit(line, parsing);
            return -1;
        }
        sscanf(tokens[6], "%"PRIu32, &(write->sector_count));
        
        if (tokens[8] == NULL)
        {
            tokenize_space_unsplit(line, parsing);
            return -1;
        }
        sscanf(tokens[8], "%"PRIu8, (unsigned int*) &(write->write));
        
        if (tokens[10] == NULL)
        {
            tokenize_space_unsplit(line, parsing);
            return -1;
        }
        sscanf(tokens[10], "%"PRIx32,   &(write->acb));
        return parsing + 1; /* +1 for final '\n' char */
    }
    else
    {
        fprintf_light_blue(stderr, "Fatal error, unknown trace message "
                                   "(not %s).\n", BDRV_CO_IO_EM);
        tokenize_space_unsplit(line, parsing);
        fprintf_light_red(stderr, "attempted to parse line: \'%s\'\n", line);
        exit(EXIT_FAILURE);
    }

    return -1;
}

int qemu_infer_binary_sector_type(struct qemu_bdrv_write write)
{
   if (write.sector_num == 0)
   {
       return SECTOR_MBR;
   } 
   if (write.sector_num > 0x03f && write.sector_num < 0x03f + 0x046a1)
   {
       return SECTOR_EXT2_PARTITION;
   }
   return SECTOR_UNKNOWN;
}

int qemu_infer_sector_type(struct qemu_bdrv_co_io_em write)
{
   if (write.sector == 0)
   {
       return SECTOR_MBR;
   } 
   if (write.sector > 0x03f && write.sector < 0x03f + 0x046a1)
   {
       return SECTOR_EXT2_PARTITION;
   }
   return SECTOR_UNKNOWN;
}

int qemu_print_sector_type(int type)
{
    switch(type)
    {
        case SECTOR_MBR:
            fprintf_light_green(stdout, "Write to MBR detected.\n");
            return 0;
        case SECTOR_EXT2_PARTITION:
            fprintf_light_green(stdout, "Write to ext2 partition detected.\n");
            return 0;
        case SECTOR_EXT2_SUPERBLOCK:
            fprintf_light_green(stdout, "Write to ext2 superblock detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR:
            fprintf_light_green(stdout, "Write to ext2 block group descriptor detected.\n");
            return 0;
        case SECTOR_EXT2_INODE:
            fprintf_light_green(stdout, "Write to ext2 inode detected.\n");
            return 0;
        case SECTOR_EXT2_DATA:
            fprintf_light_green(stdout, "Write to ext2 data block detected.\n");
            return 0;
        case SECTOR_UNKNOWN:
            fprintf_light_red(stdout, "Unknown sector type.\n");
    }

    return -1;
}
