#ifndef __XRAY_TOOLS_TAIL_H
#define __XRAY_TOOLS_TAIL_H

#include "../stream_analyzer/qemu_tracer.h"
#include "../disk_analyzer/ext2.h"

struct tail_conf
{
    char* tracked_file;
    int stream;
    uint64_t current_file_offset;
    struct ext2_inode tracked_inode; 
    uint32_t inode_sector;
    uint32_t inode_offset;
    /* struct bst bst; */
};

/* TODO: generalize and make this */
int tail_init_config(struct tail_conf* conf, char* path);

/* check inode update from before, if size changes
 * print more */
int tail_parse_inode_update(struct tail_conf* config,
                            struct qemu_bdrv_write write);

/* print out file data */
int tail_parse_file_update(struct tail_conf* config,
                           struct qemu_bdrv_write write);

/* take in raw write, check what needs to happen */
int tail_parse_block_write(struct tail_conf* config,
                           struct qemu_bdrv_write write);

#endif
