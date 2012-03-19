#include <stdlib.h>

#include "tail.h"

int tail_parse_file_update(struct tail_conf* config,
                           struct qemu_bdrv_write write)
{
    /* check offset, print out
     *
     * size = compute_file_offset(config, write);
     * offset = compute_file_offset(config, write);
     *
     * make data a string of correct length (according to file length)
     *
     * fprintf_yellow(stdout, "@%X: '%s'\n", offset, data);
     *
     * */
    return EXIT_SUCCESS;
}

int tail_parse_inode_update(struct tail_conf* config,
                            struct qemu_bdrv_write write)
{
    /* 
     * (1) compare write offset inode (cast) with size of file in
     *     config->tracked_inode
     * (2) if size changed, compute which block should contain data
     * (3) read block
     * (4) print offset till end of file bytes
     * 
     * */
    return EXIT_SUCCESS;
}

/* take in raw write, check what needs to happen */
int tail_parse_block_write(struct tail_conf* configuration,
                           struct qemu_bdrv_write write)
{
    if (configuration->inode_sector >= write.header.sector_num &&
        configuration->inode_sector <
        write.header.sector_num + write.header.nb_sectors)
    {
        /* TODO: handle inode potential change, sector got overwritten
         * 
         * tail_parse_inode_update(configuration, write);
         *
         * */
    }

    /* TODO: need a binary search tree
    if (bst_is_in(configuration->bst, write.header.sector_num))
    {
        tail_parse_file_update(configuration, write);
    }*/

    return EXIT_SUCCESS;
}
