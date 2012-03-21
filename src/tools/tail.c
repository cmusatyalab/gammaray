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

void inode_print_diff(struct ext2_inode inode1, struct ext2_inode inode2)
{
    int i;
    if (inode1.i_mode != inode2.i_mode)
        fprintf_yellow(stdout, "inode mode modified.\n");
    if (inode1.i_uid != inode2.i_uid)
        fprintf_yellow(stdout, "owner modified.\n");
    if (inode1.i_size != inode2.i_size)
        fprintf_light_yellow(stdout, "inode size modified, old=%"PRIu32" new=%"PRIu32".\n",
                                      inode1.i_size, inode2.i_size);
    if (inode1.i_atime != inode2.i_atime)
        fprintf_yellow(stdout, "inode atime modified.\n");
    if (inode1.i_ctime != inode2.i_ctime)
        fprintf_yellow(stdout, "inode ctime modified.\n");
    if (inode1.i_mtime != inode2.i_mtime)
        fprintf_yellow(stdout, "inode mtime modified.\n");
    if (inode1.i_dtime != inode2.i_dtime)
        fprintf_yellow(stdout, "inode dtime modified.\n");
    if (inode1.i_gid != inode2.i_gid)
        fprintf_yellow(stdout, "inode group modified.\n");
    if (inode1.i_links_count != inode2.i_links_count)
        fprintf_yellow(stdout, "inode links count modified.\n");
    if (inode1.i_blocks != inode2.i_blocks)
        fprintf_light_yellow(stdout, "inode block count modified.\n");
    if (inode1.i_flags != inode2.i_flags)
        fprintf_yellow(stdout, "inode flags modified.\n");
    if (inode1.i_osd1 != inode2.i_osd1)
        fprintf_yellow(stdout, "inode osd1 modified.\n");
    /* loop 15 */
    for (i = 0; i < 15; i++)
    {
        if (inode1.i_block[i] == 0 && inode2.i_block[i] != 0)
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"] added.\n", i, inode2.i_block[i]);
        else if (inode1.i_block[i] != 0 && inode2.i_block[i] == 0)
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"->%"PRIu32"] removed.\n", i, inode1.i_block[i], inode2.i_block[i]);
        else if (inode1.i_block[i] != inode2.i_block[i])
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"->%"PRIu32"] overwritten.\n", i, inode1.i_block[i], inode2.i_block[i]);
    }
    if (inode1.i_generation != inode2.i_generation)
        fprintf_yellow(stdout, "inode generation modified.\n");
    if (inode1.i_file_acl != inode2.i_file_acl)
        fprintf_yellow(stdout, "inode file_acl modified.\n");
    if (inode1.i_dir_acl != inode2.i_dir_acl)
        fprintf_yellow(stdout, "inode dir_acl modified.\n");
    if (inode1.i_faddr != inode2.i_faddr)
        fprintf_yellow(stdout, "inode faddr modified.\n");
    for (i = 0; i < 12; i++)
    {
        if (inode1.i_osd2[i] != inode2.i_osd2[i])
            fprintf_yellow(stdout, "inode osd2 byte %d modified.\n", i);
    }
}

int tail_parse_inode_update(struct tail_conf* config,
                            struct qemu_bdrv_write write)
{
    /* 
     * (0) update our metadate for this inode
     * (1) compare write offset inode (cast) with size of file in
     *     config->tracked_inode
     * (2) if size changed, compute which block should contain data
     * (3) read block
     * (4) print offset till end of file bytes
     * 
     * */
    
    int i;
    struct ext2_inode inode;
    inode = *((struct ext2_inode*)(&(write.data[config->inode_offset])));
    inode_print_diff(config->tracked_inode, inode);
    
    if (config->tracked_inode.i_size != inode.i_size)
        //config->tracked_inode.i_size = inode2.i_size;
        ;

    /* loop 15 */
    for (i = 0; i < 15; i++)
    {
        if (config->tracked_inode.i_block[i] == 0 && inode.i_block[i] != 0)
            //fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"] added.\n", i, inode2.i_block[i]);
            ;
        else if (config->tracked_inode.i_block[i] != 0 && inode.i_block[i] == 0)
            //fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"] removed.\n", i, inode2.i_block[i]);
            ;
        else if (config->tracked_inode.i_block[i] != inode.i_block[i])
            //fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"->%"PRIu32"] overwritten.\n", i, config->tracked_inode.i_block[i], inode2.i_block[i]);
            ;
    }

    config->tracked_inode = inode;

    return EXIT_SUCCESS;
}

/* take in raw write, check what needs to happen */
int tail_parse_block_write(struct tail_conf* config,
                           struct qemu_bdrv_write write)
{
    if (config->inode_sector >= write.header.sector_num &&
        config->inode_sector <
        write.header.sector_num + write.header.nb_sectors)
    {
        fprintf_light_red(stdout, "inode for %s\n", config->tracked_file);
        tail_parse_inode_update(config, write);
    }

    if (bst_find(config->bst, write.header.sector_num))
    {
        //tail_parse_file_update(config, write);
    }

    return EXIT_SUCCESS;
}
