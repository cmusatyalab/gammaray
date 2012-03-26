#include <stdlib.h>

#include "tail.h"
#include "../disk_analyzer/ext2.h"

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
    uint32_t additional_bytes = 0;
    struct ext2_inode inode;
    void* data = NULL;
    uint32_t* indirect_data = NULL;
    uint32_t offset = 0, sector_offset = config->current_file_offset % 1024;
    
    /* offset into the write, it doesn't start with our inode sector */
    if (config->inode_sector > write.header.sector_num)
    {
        offset = SECTOR_SIZE*(config->inode_sector - write.header.sector_num);
    }

    inode = *((struct ext2_inode*)
             (&(write.data[offset + config->inode_offset])));
    inode_print_diff(config->tracked_inode, inode);
    
    /* file grew in size; can not detect overwrite and file growth? TODO */
    /* TODO: maybe place after other metadata updates? */
    if (config->tracked_inode.i_size < inode.i_size && inode.i_size > config->current_file_offset)
    {
        additional_bytes = inode.i_size - config->current_file_offset;
        if (config->current_file_offset % 1024)//(config->tracked_inode.i_blocks == inode.i_blocks)
        {
            /* print the last few bytes from the last block */
            data = bst_delete(config->queue, NULL, config->last_sector);
            fprintf_light_cyan(stdout, "attempting to print bytes from last sector...\n");
            if (data)
            {
                fprintf_light_cyan(stdout, "printing from last sector=%"PRIu32"\n", config->last_sector);
                fprintf_light_cyan(stdout, "sector_offset=%"PRIu32" amount=%"PRIu32"\n", sector_offset, additional_bytes < 1024-(sector_offset) ? additional_bytes : 1024-sector_offset);
                fwrite(((uint8_t*)data) + sector_offset, 1, additional_bytes < 1024-(sector_offset) ? additional_bytes : 1024-sector_offset, stdout);
                config->current_file_offset += additional_bytes < 1024-(sector_offset) ? additional_bytes : 1024-sector_offset;
                fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                additional_bytes -= additional_bytes < 1024-(sector_offset) ? additional_bytes : 1024-sector_offset;
                //free(data);
            }
        }
    }
    else if (config->tracked_inode.i_size > 0 && inode.i_size == 0) /* new size is 0... */
    {
        fprintf_light_red(stderr, "tail: possible file truncation detected."
                                  "\n");
    }

    /* loop 15 */
    for (i = 0; i < 15; i++)
    {
        if (config->tracked_inode.i_block[i] == 0 && inode.i_block[i] != 0 && i < 12)
        {
            fprintf_light_red(stdout, "additional_bytes: %"PRIu32"\n", additional_bytes);
            if (additional_bytes >= SECTOR_SIZE*2 && inode.i_size > config->current_file_offset)
            {
                fprintf_light_cyan(stdout, "NEW BLOCK writing full block\n");
                data = bst_delete(config->queue, NULL, ext2_sector_from_block(inode.i_block[i]));
                if (data)
                {
                    fprintf_light_cyan(stdout, "pulled data for sector: %"PRIu64"\n", ext2_sector_from_block(inode.i_block[i]));
                    fwrite(data, 1, SECTOR_SIZE*2, stdout);
                    config->current_file_offset += SECTOR_SIZE*2;
                    fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                    additional_bytes -= SECTOR_SIZE*2;
                    //free(data);
                }
                config->last_sector = ext2_sector_from_block(inode.i_block[i]);
                bst_insert(config->bst, config->last_sector, (void*) 1);
                bst_insert(config->bst, config->last_sector + 1, (void*) 1);
            }
            else if (inode.i_size > config->current_file_offset)
            {
                fprintf_light_cyan(stdout, "NEW BLOCK writing partial block\n");
                data = bst_delete(config->queue, NULL, ext2_sector_from_block(inode.i_block[i]));
                if (data)
                {
                    fprintf_light_cyan(stdout, "pulled data for sector: %"PRIu64"\n", ext2_sector_from_block(inode.i_block[i]));
                    fwrite(data, 1, additional_bytes, stdout);
                    config->current_file_offset += additional_bytes;
                    fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                    additional_bytes -= additional_bytes;
                    //free(data);
                }
                config->last_sector = ext2_sector_from_block(inode.i_block[i]);
                bst_insert(config->bst, config->last_sector, (void*) 1);
                bst_insert(config->bst, config->last_sector + 1, (void*) 1);
            }
        }
        else if (config->tracked_inode.i_block[i] == 0 && inode.i_block[i] != 0 && i == 12)
        {
            fprintf_light_cyan(stdout, "indirect block at sector: %"PRIu32"\n",ext2_sector_from_block(inode.i_block[i]) );
            indirect_data = (uint32_t*) bst_find(config->queue, ext2_sector_from_block(inode.i_block[i]));
            if (indirect_data)
            {
                fprintf_light_cyan(stdout, "checking data block %"PRIu32" or sector %"PRIu32"\n", *indirect_data, ext2_sector_from_block(*indirect_data));
                while (*(indirect_data))
                {
                    if (additional_bytes >= SECTOR_SIZE*2 && inode.i_size > config->current_file_offset)
                    {
                        data = bst_delete(config->queue, NULL, ext2_sector_from_block(*indirect_data));
                        if (data)
                        {
                            fwrite(data, 1, SECTOR_SIZE*2, stdout);
                            config->current_file_offset += SECTOR_SIZE*2;
                            fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                            additional_bytes -= SECTOR_SIZE*2;
                            //free(data);
                        }
                        config->last_sector = ext2_sector_from_block(*indirect_data);
                        bst_insert(config->bst, config->last_sector, (void*) 1);
                        bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                    }
                    else if (inode.i_size > config->current_file_offset)
                    {
                        data = bst_delete(config->queue, NULL, ext2_sector_from_block(*indirect_data));
                        if (data)
                        {
                            fwrite(data, 1, additional_bytes, stdout);
                            config->current_file_offset += additional_bytes;
                            fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                            additional_bytes -= additional_bytes;
                           // free(data);
                        }
                        config->last_sector = ext2_sector_from_block(*indirect_data);
                        bst_insert(config->bst, config->last_sector, (void*) 1);
                        bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                    }
                    indirect_data += 1;
                }
                //free(bst_delete(config->queue, NULL, ext2_sector_from_block(inode.i_block[i])));
            }
            bst_insert(config->bst, ext2_sector_from_block(inode.i_block[i]), (void*)1);
        }
        else if (config->tracked_inode.i_block[i] == 0 && inode.i_block[i] != 0 && i == 13)
        {
            fprintf_light_red(stderr, "TODO: handle doubly indirect block.\n");
            /* TODO: handle doubly indirect block */
        }
        else if (config->tracked_inode.i_block[i] == 0 && inode.i_block[i] != 0 && i == 14)
        {
            fprintf_light_red(stderr, "TODO: handle triply indirect block.\n");
            /* TODO: handle triply indirect block */
        }
        else if (config->tracked_inode.i_block[i] != 0 && inode.i_block[i] == 0)
        {
            if (config->last_sector == ext2_sector_from_block(inode.i_block[i]))
            {
                config->last_sector = 0;
            }    
        }
        else if (config->tracked_inode.i_block[i] != inode.i_block[i])
        {
            if (config->last_sector == ext2_sector_from_block(inode.i_block[i]))
            {
                config->last_sector = 0;
            }
        }
    }

    /* ugly cleanup tracking indirect block changes */
    if (inode.i_block[12] && config->current_file_offset < inode.i_size && bst_find(config->queue, ext2_sector_from_block(inode.i_block[12])))
    {
        fprintf_light_red(stdout, "UGLY CLEANUP\n");
        fprintf_light_cyan(stdout, "indirect block at sector: %"PRIu32"\n",ext2_sector_from_block(inode.i_block[12]) );
        indirect_data = (uint32_t*) bst_find(config->queue, ext2_sector_from_block(inode.i_block[12]));
        uint32_t num_in_indirect_block = config->current_file_offset / 1024 - 12;
        indirect_data += num_in_indirect_block;
        if (indirect_data)
        {
            fprintf_light_cyan(stdout, "checking data block %"PRIu32" or sector %"PRIu32"\n", *indirect_data, ext2_sector_from_block(*indirect_data));
            while (*(indirect_data))
            {
                uint64_t offset = config->current_file_offset % 1024;
                additional_bytes = inode.i_size - config->current_file_offset;
                data = bst_delete(config->queue, NULL, ext2_sector_from_block(*indirect_data));
                if (data == NULL)
                    break;
                if (data && offset)
                {
                    if (additional_bytes == 0)
                    {
                        fprintf_light_red(stdout, "reinserting indirect block update into queue\n");
                        bst_insert(config->queue, ext2_sector_from_block(*indirect_data), data);
                        break;
                    }
                    fwrite(data+offset, 1, additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes, stdout);
                    additional_bytes -= additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes;
                    config->current_file_offset += additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes;
                    fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                    fprintf_light_cyan(stdout, "jumping to next indirect data block\n");
                    indirect_data += 1;
                    continue;
                }
                if (additional_bytes >= SECTOR_SIZE*2 && inode.i_size > config->current_file_offset)
                {
                    if (data)
                    {
                        fwrite(data, 1, SECTOR_SIZE*2, stdout);
                        config->current_file_offset += SECTOR_SIZE*2;
                        fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                        additional_bytes -= SECTOR_SIZE*2;
                        //free(data);
                    }
                    config->last_sector = ext2_sector_from_block(*indirect_data);
                    bst_insert(config->bst, config->last_sector, (void*) 1);
                    bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                }
                else if (inode.i_size > config->current_file_offset)
                {
                    if (data)
                    {
                        fwrite(data, 1, additional_bytes, stdout);
                        config->current_file_offset += additional_bytes;
                        fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                        additional_bytes -= additional_bytes;
                        // free(data);
                    }
                    config->last_sector = ext2_sector_from_block(*indirect_data);
                    bst_insert(config->bst, config->last_sector, (void*) 1);
                    bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                }
                indirect_data += 1;
            }
            //free(bst_delete(config->queue, NULL, ext2_sector_from_block(inode.i_block[i])));
        }
        bst_insert(config->bst, ext2_sector_from_block(inode.i_block[i]), (void*)1);
    }

    config->tracked_inode = inode;

    return EXIT_SUCCESS;
}

void update_last_sector(struct tail_conf* config)
{
    fprintf_light_red(stdout, "UPDATING LAST SECTOR FUN\n");
    int sector = config->current_file_offset / 1024;
    uint32_t* indirect_data;
    if (sector < 12)
        config->last_sector = config->tracked_inode.i_block[sector];
    else
    {
        indirect_data = (uint32_t*) bst_find(config->queue, ext2_sector_from_block(config->tracked_inode.i_block[12]));
        if (indirect_data == NULL)
        {
            fprintf_light_red(stdout, "indirect_data WAS NULL\n");
            return;
        }
        indirect_data += sector - 12;
        config->last_sector = *indirect_data;
    }
}

/* take in raw write, check what needs to happen */
int tail_parse_block_write(struct tail_conf* config,
                           struct qemu_bdrv_write write)
{
    int i, additional_bytes = 0, offset = 0, num_in_indirect_block = 0;
    uint32_t* indirect_data;
    uint8_t *data;
    struct ext2_inode inode = config->tracked_inode;

    if (config->inode_sector >= write.header.sector_num &&
        config->inode_sector <
        write.header.sector_num + write.header.nb_sectors)
    {
        fprintf_light_red(stdout, "inode for %s\n", config->tracked_file);
        tail_parse_inode_update(config, write);
    }

    /* TODO: Hard coded block size... */
    for (i = 0; i < write.header.nb_sectors; i += 2)
    {
        if (bst_find(config->bst, write.header.sector_num+i))
        {
            fprintf_light_cyan(stdout, "checking data sector: %"PRIu32"\n", write.header.sector_num+i);
            offset = 0;
            if (write.header.sector_num+i == ext2_sector_from_block(config->tracked_inode.i_block[12]))
            {
                additional_bytes = inode.i_size - config->current_file_offset;
                fprintf_light_cyan(stdout, "indirect block _after_ inode update at sector: %"PRIu32"\n",ext2_sector_from_block(inode.i_block[12]));
                indirect_data = (uint32_t*) bst_find(config->queue, ext2_sector_from_block(inode.i_block[12]));
                num_in_indirect_block = config->current_file_offset / 1024 - 12;
                indirect_data += num_in_indirect_block;
                fprintf_light_cyan(stdout, "offset: %d\n", offset);
                if (indirect_data)
                {
                    while (*(indirect_data))
                    {
                        offset = config->current_file_offset % 1024;
                        fprintf_light_cyan(stdout, "checking data block %"PRIu32" or sector %"PRIu32"\n", *indirect_data, ext2_sector_from_block(*indirect_data));
                        /* TODO: BUG on bst_delete */
                        data = bst_find(config->queue, ext2_sector_from_block(*indirect_data));
                        if (data == NULL)
                            break; /* the guy we want doesnt exist? */
                        if (data && offset)
                        {
                            if (additional_bytes == 0)
                            {
                                fprintf_light_red(stdout, "reinserting indirect block update into queue\n");
                                bst_insert(config->queue, ext2_sector_from_block(*indirect_data), data);
                                break;
                            }
                            fwrite(data+offset, 1, additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes, stdout);
                            additional_bytes -= additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes;
                            config->current_file_offset += additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes;
                            fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                            fprintf_light_cyan(stdout, "jumping to next indirect data block\n");
                            indirect_data += 1;
                            continue;
                        }
                        if (additional_bytes >= SECTOR_SIZE*2 && inode.i_size > config->current_file_offset)
                        {
                            if (data)
                            {
                                fwrite(data, 1, SECTOR_SIZE*2, stdout);
                                config->current_file_offset += SECTOR_SIZE*2;
                                fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                                additional_bytes -= SECTOR_SIZE*2;
                                //free(data);
                            }
                            config->last_sector = ext2_sector_from_block(*indirect_data);
                            bst_insert(config->bst, config->last_sector, (void*) 1);
                            bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                        }
                        else if (inode.i_size > config->current_file_offset)
                        {
                            if (data)
                            {
                                fwrite(data, 1, additional_bytes, stdout);
                                config->current_file_offset += additional_bytes;
                                fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, inode.i_size, config->last_sector);
                                additional_bytes -= additional_bytes;
                               // free(data);
                            }
                            config->last_sector = ext2_sector_from_block(*indirect_data);
                            bst_insert(config->bst, config->last_sector, (void*) 1);
                            bst_insert(config->bst, config->last_sector + 1, (void*) 1);
                        }
                        indirect_data += 1;
                    }
                    //free(bst_delete(config->queue, NULL, ext2_sector_from_block(inode.i_block[i])));
                }
            }
            else
            {
                /* TODO: BUG on bst_delete */
                bst_find(config->queue, write.header.sector_num+i);
                if (config->last_sector == write.header.sector_num+i)
                {
                    offset = config->current_file_offset % 1024;
                    fprintf_light_red(stdout, "current sector offset: %d\n", offset);
                    additional_bytes = config->tracked_inode.i_size - config->current_file_offset;
                    additional_bytes = additional_bytes > 1024 - offset ? 1024 - offset : additional_bytes; 
                 }
                 /* data write _after_ metadata update... */
                 if (additional_bytes > 0 && additional_bytes >= 1024)
                 {
                     fwrite(&(write.data[i*512+offset]), 1, 1024, stdout);
                     config->current_file_offset += 1024;
                     fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, config->tracked_inode.i_size, config->last_sector);
                     //update_last_sector(config);
                 }
                 else if (additional_bytes > 0)
                 {
                     fwrite(&(write.data[i*512+offset]), 1, additional_bytes, stdout);
                     config->current_file_offset += additional_bytes;
                     fprintf_light_cyan(stdout, "current_file_offset: %"PRIu64" i_size: %"PRIu32" last_sector: %"PRIu32"\n", config->current_file_offset, config->tracked_inode.i_size, config->last_sector);
                     //update_last_sector(config);
                 }
                 else if (additional_bytes < 0)
                 {
                     fprintf_light_red(stderr, "breaking, as additional_bytes < 0\n");
                     break;
                 }
            }

            tail_parse_file_update(config, write); /* --> tail does nothing on prior updates? */
        }
    }

    return EXIT_SUCCESS;
}
