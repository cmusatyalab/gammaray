#include "qemu_tracer.h"
#include "../disk_analyzer/color.h"
#include "tokenizer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int64_t qemu_sizeof_header()
{
    return QEMU_HEADER_SIZE;
}

int qemu_print_write(struct qemu_bdrv_write write)
{
    fprintf_light_blue(stdout, "brdv_write event\n");
    fprintf_yellow(stdout, "\tsector_num: %0."PRId64"\n",
                           write.header.sector_num);
    fprintf_yellow(stdout, "\tnb_sectors: %d\n",
                           write.header.nb_sectors);
    fprintf_yellow(stdout, "\tdata buffer pointer (malloc()'d): %p\n",
                           write.data);
    return 0;
}

int64_t qemu_parse_header(uint8_t* event_stream,
                                 struct qemu_bdrv_write* write)
{
    write->header = *((struct qemu_bdrv_write_header*) event_stream);
    return 0;
}

/*
 * MBR Start Sector 0
 * MBR End Sector 0
 * Partition Sector Start 63
 * Partition Sector End 18144
 * Superblock sector 65
 * BGD 0
 * Start Sector 4
 * bg_block_bitmap sector 139
 * bg_inode_bitmap sector 141
 * bg_inode_table sector start 143
 * bg_inode_table sector end 427
 * BGD end sector 16523
 * BGD 1
 * Start Sector 4
 * bg_block_bitmap sector 16523
 * bg_inode_bitmap sector 16525
 * bg_inode_table sector start 16527
 * bg_inode_table sector end 16811
 * BGD end sector 32907
 *
 * */
int qemu_infer_sector_type(struct qemu_bdrv_write write)
{
   if (write.header.sector_num == 0)
   {
       return SECTOR_MBR;
   } 
   if (write.header.sector_num > 0x03f && write.header.sector_num < 0x03f + 0x046a1)
   {
       if (write.header.sector_num == 65)
           return SECTOR_EXT2_SUPERBLOCK;
       if (write.header.sector_num <= 67)
           return SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR;
       if (write.header.sector_num == 139)
           return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP;
       if (write.header.sector_num == 141)
           return SECTOR_EXT2_BLOCK_GROUP_INODEMAP;
       if (write.header.sector_num >= 143 && write.header.sector_num < 427)
           return SECTOR_EXT2_INODE;
       if (write.header.sector_num >= 427 && write.header.sector_num < 16523)
           return SECTOR_EXT2_DATA;
       if (write.header.sector_num == 16523)
           return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP;
       if (write.header.sector_num == 16525)
           return SECTOR_EXT2_BLOCK_GROUP_INODEMAP;
       if (write.header.sector_num >= 16527 && write.header.sector_num < 16811)
           return SECTOR_EXT2_INODE;
       if (write.header.sector_num >= 16811)
           return SECTOR_EXT2_DATA;
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
        case SECTOR_EXT2_SUPERBLOCK:
            fprintf_light_green(stdout, "Write to ext2 superblock detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR:
            fprintf_light_green(stdout, "Write to ext2 block group descriptor detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP:
            fprintf_light_green(stdout, "Write to ext2 block group block map detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_INODEMAP:
            fprintf_light_green(stdout, "Write to ext2 block group inode map detected.\n");
            return 0;
        case SECTOR_EXT2_INODE:
            fprintf_light_green(stdout, "Write to ext2 inode detected.\n");
            return 0;
        case SECTOR_EXT2_DATA:
            fprintf_light_green(stdout, "Write to ext2 data block detected.\n");
            return 0;
        case SECTOR_EXT2_PARTITION:
            fprintf_light_green(stdout, "Write to ext2 partition detected.\n");
            return 0;
        case SECTOR_UNKNOWN:
            fprintf_light_red(stdout, "Unknown sector type.\n");
    }

    return -1;
}
