#define _GNU_SOURCE
#include "color.h"
#include "deep_inspection.h"
#include "ext4.h"
#include "__bson.h"
#include "bson.h"
#include "redis_queue.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

#ifndef HOST_NAME_MAX
    #define HOST_NAME_MAX 256
#endif

#define FILE_DATA_WRITE "data"
#define FILE_META_WRITE "metadata"
#define VM_NAME_MAX 512
#define PATH_MAX 4096

char* construct_channel_name(char* vmname, char* path)
{
    char* buf = malloc(HOST_NAME_MAX + VM_NAME_MAX + PATH_MAX + 3);
    if (buf == NULL)
        return NULL;

    if (gethostname(buf, HOST_NAME_MAX))
    {
        free(buf);
        return NULL;
    }

    strncat(buf, ":", 1);
    strncat(buf, vmname, strlen(vmname));
    strncat(buf, ":", 1);
    strncat(buf, path, strlen(path));
    return buf;
}

void qemu_free(void* data, void* hint)
{
    free(data);
}

char* clone_cstring(char* cstring)
{
    char* ret = malloc(strlen(cstring) + 1);
    if (ret == NULL)
        return NULL;
    strcpy(ret, cstring);
    return ret;
}

int qemu_print_write(struct qemu_bdrv_write* write)
{
    fprintf_light_blue(stdout, "brdv_write event\n");
    fprintf_yellow(stdout, "\tsector_num: %0."PRId64"\n",
                           write->header.sector_num);
    fprintf_yellow(stdout, "\tnb_sectors: %d\n",
                           write->header.nb_sectors);
    fprintf_yellow(stdout, "\tdata buffer pointer (malloc()'d): %p\n",
                           write->data);
    return 0;
}

void print_ext4_file(struct ext4_file* file)
{
    fprintf_light_cyan(stdout, "-- ext4 File --\n");
    fprintf_yellow(stdout, "file->inode_sector == %"PRIu64"\n",
                            file->inode_sector);
    fprintf_yellow(stdout, "file->inode_offset == %"PRIu64"\n",
                            file->inode_offset);
    fprintf_yellow(stdout, "file->is_dir == %s\n",
                            file->is_dir ? "true" : "false");
    fprintf_yellow(stdout, "file->inode == %p\n", &(file->inode));
}

void print_ext4_bgd(struct ext4_bgd* bgd)
{
    fprintf_light_cyan(stdout, "-- ext4 BGD --\n");
    fprintf_yellow(stdout, "bgd->bgd == %p\n", &(bgd->bgd));
    fprintf_yellow(stdout, "bgd->sector == %"PRIu64"\n", bgd->sector);
    fprintf_yellow(stdout, "bgd->block_bitmap_sector_start == %"PRIu64"\n",
                            bgd->block_bitmap_sector_start);
    fprintf_yellow(stdout, "bgd->block_bitmap_sector_end == %"PRIu64"\n",
                            bgd->block_bitmap_sector_end);
    fprintf_yellow(stdout, "bgd->inode_bitmap_sector_start == %"PRIu64"\n",
                            bgd->inode_bitmap_sector_start);
    fprintf_yellow(stdout, "bgd->inode_bitmap_sector_end == %"PRIu64"\n",
                            bgd->inode_bitmap_sector_end);
    fprintf_yellow(stdout, "bgd->inode_table_sector_start == %"PRIu64"\n",
                            bgd->inode_table_sector_start);
    fprintf_yellow(stdout, "bgd->inode_table_sector_end == %"PRIu64"\n",
                            bgd->inode_table_sector_end);
}

void print_ext4_fs(struct ext4_fs* fs)
{
    fprintf_light_cyan(stdout, "-- ext4 FS --\n");
    fprintf_yellow(stdout, "fs->fs_type %"PRIu64"\n", fs->fs_type);
    fprintf_yellow(stdout, "fs->mount_point %s\n", fs->mount_point);
    fprintf_yellow(stdout, "fs->num_block_groups %"PRIu64"\n",
                            fs->num_block_groups);
    fprintf_yellow(stdout, "fs->num_files %"PRIu64"\n", fs->num_files);
}

void print_partition(struct linkedlist* pt)
{
    struct partition* pte;
    uint64_t i;

    for (i = 0; i < linkedlist_size(pt); i++)
    {
        pte = linkedlist_get(pt, i);
        fprintf_light_cyan(stdout, "-- Partition --\n");
        fprintf_yellow(stdout, "pte->pte_num == %"PRIu64"\n", pte->pte_num);
        fprintf_yellow(stdout, "pte->partition_type == %"PRIu64"\n",
                                pte->partition_type);
        fprintf_yellow(stdout, "pte->first_sector_lba == %"PRIu64"\n",
                                pte->first_sector_lba);
        fprintf_yellow(stdout, "pte->final_sector_lba == %"PRIu64"\n",
                                pte->final_sector_lba);
        fprintf_yellow(stdout, "pte->sector == %"PRIu64"\n", pte->sector);
        fprintf_yellow(stdout, "pte->fs == %p\n", &(pte->fs));
        print_ext4_fs(&(pte->fs));
    }
}

void print_mbr(struct mbr* mbr)
{
    fprintf_light_cyan(stdout, "-- MBR --\n");
    fprintf_yellow(stdout, "mbr->gpt == %d\n", mbr->gpt);
    fprintf_yellow(stdout, "mbr->sector == %"PRIu64"\n", mbr->sector);
    fprintf_yellow(stdout, "mbr->active_partitions == %"PRIu64"\n",
                            mbr->active_partitions);
}

void qemu_parse_header(uint8_t* event_stream, struct qemu_bdrv_write* write)
{
    write->header = *((struct qemu_bdrv_write_header*) event_stream);
}

int qemu_print_sector_type(enum SECTOR_TYPE type)
{
    switch(type)
    {
        case SECTOR_MBR:
            fprintf_light_green(stdout, "Write to MBR detected.\n");
            return 0;
        case SECTOR_EXT2_SUPERBLOCK:
            fprintf_light_green(stdout, "Write to ext4 superblock detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR:
            fprintf_light_green(stdout, "Write to ext4 block group descriptor detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP:
            fprintf_light_green(stdout, "Write to ext4 block group block map detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_INODEMAP:
            fprintf_light_green(stdout, "Write to ext4 block group inode map detected.\n");
            return 0;
        case SECTOR_EXT2_INODE:
            fprintf_light_green(stdout, "Write to ext4 inode detected.\n");
            return 0;
        case SECTOR_EXT2_DATA:
            fprintf_light_green(stdout, "Write to ext4 data block detected.\n");
            return 0;
        case SECTOR_EXT2_PARTITION:
            fprintf_light_green(stdout, "Write to ext4 partition detected.\n");
            return 0;
        case SECTOR_EXT4_EXTENT:
            fprintf_light_green(stdout, "Write to ext4 extents detected.\n");
        case SECTOR_UNKNOWN:
            fprintf_light_red(stdout, "Unknown sector type.\n");
    }

    return -1;
}


int ext2_compare_inodes(struct ext2_inode* old_inode,
                        struct ext2_inode* new_inode, struct kv_store* store,
                        char* vmname, char* path)
{
    uint64_t i;
    char* channel_name;
    struct bson_info* bson;
    struct bson_kv val;
    uint64_t old, new;

    bson = bson_init();

    if (old_inode->i_mode != new_inode->i_mode)
    {
        fprintf_yellow(stdout, "inode mode modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_mode");
        val.key = "type";
        val.data = "inode.i_mode";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_mode;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_mode;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_uid != new_inode->i_uid)
    {
        fprintf_yellow(stdout, "owner modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_uid");
        val.key = "type";
        val.data = "inode.i_uid";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_uid;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_uid;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_size != new_inode->i_size)
    {
        fprintf_light_yellow(stdout, "inode size modified, old=%"PRIu32" new=%"PRIu32".\n",
                                      old_inode->i_size, new_inode->i_size);
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_size");
        val.key = "type";
        val.data = "inode.i_size";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_size;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_size;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_atime != new_inode->i_atime)
    {
        fprintf_yellow(stdout, "inode atime modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_atime");
        val.key = "type";
        val.data = "inode.i_atime";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_atime;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_atime;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_ctime != new_inode->i_ctime)
    {
        fprintf_yellow(stdout, "inode ctime modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_ctime");
        val.key = "type";
        val.data = "inode.i_ctime";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_ctime;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_ctime;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_mtime != new_inode->i_mtime)
    {
        fprintf_yellow(stdout, "inode mtime modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_mtime");
        val.key = "type";
        val.data = "inode.i_mtime";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_mtime;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_mtime;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }
        
    if (old_inode->i_dtime != new_inode->i_dtime)
    {
        fprintf_yellow(stdout, "inode dtime modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_dtime");
        val.key = "type";
        val.data = "inode.i_dtime";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_dtime;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_dtime;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_gid != new_inode->i_gid)
    {
        fprintf_yellow(stdout, "inode group modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_gid");
        val.key = "type";
        val.data = "inode.i_gid";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_gid;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_gid;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_links_count != new_inode->i_links_count)
    {
        fprintf_yellow(stdout, "inode links count modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_links_count");
        val.key = "type";
        val.data = "inode.i_links_count";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_links_count;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_links_count;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_blocks != new_inode->i_blocks)
    {
        fprintf_light_yellow(stdout, "inode block count modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_blocks");
        val.key = "type";
        val.data = "inode.i_blocks";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_blocks;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_blocks;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_flags != new_inode->i_flags)
    {
        fprintf_yellow(stdout, "inode flags modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_flags");
        val.key = "type";
        val.data = "inode.i_flags";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_flags;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_flags;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_osd1 != new_inode->i_osd1)
    {
        fprintf_yellow(stdout, "inode osd1 modified.\n");
    
        val.type = BSON_STRING;
        val.size = strlen("inode.i_osd1");
        val.key = "type";
        val.data = "inode.i_osd1";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_osd1;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_osd1;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    /* loop 15 */
    for (i = 0; i < 15; i++)
    {
        if (old_inode->i_block[i] == 0 && new_inode->i_block[i] != 0)
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"] added.\n", i, new_inode->i_block[i]);
        else if (old_inode->i_block[i] != 0 && new_inode->i_block[i] == 0)
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"->%"PRIu32"] removed.\n", i, old_inode->i_block[i], new_inode->i_block[i]);
        else if (old_inode->i_block[i] != new_inode->i_block[i])
            fprintf_light_yellow(stdout, "inode block position %d [%"PRIu32"->%"PRIu32"] overwritten.\n", i, old_inode->i_block[i], new_inode->i_block[i]);


        if (old_inode->i_block[i] != new_inode->i_block[i])
        {
            val.type = BSON_STRING;
            val.size = strlen("inode.i_block");
            val.key = "type";
            val.data = "inode.i_block";

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "index";
            val.data = &(i);

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "old";
            old = old_inode->i_block[i];
            val.data = &(old);

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "new";
            new = new_inode->i_block[i];
            val.data = &(new);

            bson_serialize(bson, &val);
            bson_finalize(bson);
            
            channel_name = construct_channel_name(vmname, path);

            if (redis_publish(store, channel_name, bson->buffer, bson->position))
            {
                fprintf_light_red(stderr, "Failure publishing "
                                          "Redis message.\n");
                return -1;
            }

            free(channel_name);
            bson_reset(bson);
        }
    }

    if (old_inode->i_generation != new_inode->i_generation)
    {
        fprintf_yellow(stdout, "inode generation modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_generation");
        val.key = "type";
        val.data = "inode.i_generation";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_generation;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_generation;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_file_acl != new_inode->i_file_acl)
    {
        fprintf_yellow(stdout, "inode file_acl modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_file_acl");
        val.key = "type";
        val.data = "inode.i_file_acl";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_file_acl;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_file_acl;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_dir_acl != new_inode->i_dir_acl)
    {
        fprintf_yellow(stdout, "inode dir_acl modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_dir_acl");
        val.key = "type";
        val.data = "inode.i_dir_acl";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_dir_acl;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_dir_acl;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    if (old_inode->i_faddr != new_inode->i_faddr)
    {
        fprintf_yellow(stdout, "inode faddr modified.\n");

        val.type = BSON_STRING;
        val.size = strlen("inode.i_faddr");
        val.key = "type";
        val.data = "inode.i_faddr";

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "old";
        old = old_inode->i_faddr;
        val.data = &(old);

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "new";
        new = new_inode->i_faddr;
        val.data = &(new);

        bson_serialize(bson, &val);
        bson_finalize(bson);
        
        channel_name = construct_channel_name(vmname, path);

        if (redis_publish(store, channel_name, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return -1;
        }

        free(channel_name);
        bson_reset(bson);
    }

    for (i = 0; i < 12; i++)
    {
        if (old_inode->i_osd2[i] != new_inode->i_osd2[i])
        {
            fprintf_yellow(stdout, "inode osd2 byte %d modified.\n", i);

            val.type = BSON_STRING;
            val.size = strlen("inode.i_osd2");
            val.key = "type";
            val.data = "inode.i_osd2";

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "index";
            val.data = &(i);

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "old";
            old = old_inode->i_osd2[i];
            val.data = &(old);

            bson_serialize(bson, &val);

            val.type = BSON_INT64;
            val.key = "new";
            new = new_inode->i_osd2[i];
            val.data = &(new);

            bson_serialize(bson, &val);
            bson_finalize(bson);
            
        
            channel_name = construct_channel_name(vmname, path);

            if (redis_publish(store, channel_name, bson->buffer, bson->position))
            {
                fprintf_light_red(stderr, "Failure publishing "
                                          "Redis message.\n");
                return -1;
            }

            free(channel_name);
            bson_reset(bson);
        }
    }
    
    *old_inode = *new_inode;

    bson_cleanup(bson);

    return EXIT_SUCCESS;
}

int qemu_deep_inspect(struct qemu_bdrv_write* write, struct kv_store* store,
                      char* vmname, uint64_t block_size)
{
    uint32_t i;
    uint8_t lookup[1024];
    size_t len;

    for (i = 0; i < write->header.nb_sectors; i += block_size / SECTOR_SIZE)
    {
        len = 1024;
        if (redis_sector_lookup(store, write->header.sector_num + i, lookup, &len))
        {
            fprintf_light_red(stdout, "Unknown file path.\n");
            continue;
        }

        if (len)
        {
            fprintf_light_green(stdout, "Write detected: '%s'\n", lookup);
        }
        else /* handling unknown write, send to queue */
        {
            for (i = 0; i < write->header.nb_sectors; i++)
            {
                redis_enqueue_pipelined(store, write->header.sector_num + i,
                                               &(write->data[i*SECTOR_SIZE]),
                                               SECTOR_SIZE);
            }
        }
    }
    return EXIT_SUCCESS;
}

uint64_t qemu_get_block_size(struct kv_store* store, uint64_t fs_id)
{
    struct ext4_superblock super;
    size_t len = sizeof(super);

    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET,
                             fs_id, "superblock", (uint8_t*) &super, &len))
    {
        fprintf_light_red(stderr, "Error retrieving superblock\n");
        return 0;
    }

    return ext4_block_size(super);
}

enum SECTOR_TYPE __sector_type(const char* str)
{
    if (strncmp(str, "start", strlen("start")) == 0)
        return SECTOR_EXT2_DATA;
    else if(strncmp(str, "superblock", strlen("superblock")))
        return SECTOR_EXT2_SUPERBLOCK;
    else if(strncmp(str, "mbr", strlen("mbr")))
        return SECTOR_MBR;
    else if(strncmp(str, "lbgds", strlen("lbgds")))
        return SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR;
    else if(strncmp(str, "linodes", strlen("linodes")))
        return SECTOR_EXT2_INODE;
    else if(strncmp(str, "bgd", strlen("bgd")))
        return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP |
               SECTOR_EXT2_BLOCK_GROUP_INODEMAP;
    else if(strncmp(str, "lextents", strlen("lextents")))
        return SECTOR_EXT4_EXTENT;
    fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                    str);
    return SECTOR_UNKNOWN;
}

enum SECTOR_TYPE qemu_infer_sector_type(struct qemu_bdrv_write* write,
                                        struct kv_store* store,
                                        uint64_t block_size)
{
    uint64_t i, id;
    uint8_t result[1024];
    size_t len = 1024;

    for (i = 0; i < write->header.nb_sectors; i += block_size / SECTOR_SIZE)
    {
        if (redis_sector_lookup(store, write->header.sector_num + i,
            result, &len))
        {
            fprintf_light_red(stderr, "Error doing sector lookup.\n");
            return SECTOR_UNKNOWN;
        } 

        if (len)
        {
            sscanf((const char*) result, "%s:%"SCNu64, result, &id);
            fprintf_light_green(stdout, "Inference got: %s:%"PRIu64"\n",
                                                        result, id);
            return __sector_type((const char*) result);
        }
        else
        {
            return SECTOR_UNKNOWN;
        }
    }

    return SECTOR_UNKNOWN;
}

/*
int qemu_infer_sector_type(struct qemu_bdrv_write* write, 
                           uint64_t mbr_id, struct kv_store* store,
                           uint64_t block_size)
{
    uint64_t i, j;
    struct ext2_superblock super;
    struct ext2_bgd bgd;
    uint32_t mbr_sector, active_partitions;
    uint32_t first_sector, last_sector;
    uint32_t num_block_groups;
    size_t len = sizeof(uint32_t);

    uint64_t blocks_per_block_group, sectors_per_block_group,
             start_sector, bgd_start, bgd_end;

    if (redis_hash_get(store, "mbr", mbr_id, "sector", (uint8_t*) &mbr_sector,
                       &len))
    {
        fprintf_light_red(stderr, "Error retrieving mbr sector.\n");
        return SECTOR_UNKNOWN;
    }

    if (redis_hash_get(store, "mbr", mbr_id, "partitions",
                       (uint8_t*) &active_partitions, &len))
    {
        fprintf_light_red(stderr, "Error retrieving active partitions.\n");
        return SECTOR_UNKNOWN;
    }

    if (write->header.sector_num == mbr_sector)
        return SECTOR_MBR;

    for (i = 0; i < active_partitions; i++)
    {
         if (redis_hash_get(store, "pte", i, "first_sector_lba", (uint8_t*)
                            &first_sector, &len))
         {
            fprintf_light_red(stderr, "Error retrieving first sector lba.\n");
            return SECTOR_UNKNOWN;
         }

         if (redis_hash_get(store, "pte", i, "final_sector_lba", (uint8_t*)
                            &last_sector, &len))
         {
            fprintf_light_red(stderr, "Error retrieving last sector lba \n");
            return SECTOR_UNKNOWN;
         }

         fprintf_light_cyan(stderr, "first_sector_lba: %"PRIu32
                                    " last_sector_lba: %"PRIu32"\n",
                                    first_sector, last_sector);

        if (write->header.sector_num <= last_sector &&
            write->header.sector_num >= first_sector)
        {
            if (write->header.sector_num == first_sector + 2)
                return SECTOR_EXT2_SUPERBLOCK;

            len = sizeof(super);
            if (redis_hash_get(store, "fs", 0, "superblock", (uint8_t*) &super,
                               &len))
            {
                fprintf_light_red(stderr, "Error retrieving superblock\n");
                return SECTOR_UNKNOWN;
            }

            blocks_per_block_group = super.s_blocks_per_group;
            sectors_per_block_group = blocks_per_block_group *
                                      (block_size / SECTOR_SIZE);
            start_sector = super.s_first_data_block *
                           (block_size / SECTOR_SIZE) +
                           first_sector;

            len = sizeof(num_block_groups);
            if (redis_hash_get(store, "fs", 0, "num_block_groups",
                               (uint8_t*) &num_block_groups, &len))
            {
                fprintf_light_red(stderr, "Error retrieving num block "
                                          "groups\n");
                return SECTOR_UNKNOWN;
            }

            for (j = 0; j < num_block_groups; j++)
            {
                bgd_start = start_sector + sectors_per_block_group * j;
                bgd_end = bgd_start + sectors_per_block_group - 1;
                len = sizeof(bgd);
                if (redis_hash_get(store, "bgd", j, "bgd", (uint8_t*) &(bgd),
                                   &len))
                {
                    fprintf_light_red(stderr, "Error retrieving bgd\n");
                    return SECTOR_UNKNOWN;
    
            }

                if (write->header.sector_num == bgd.sector)
                    return SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR;

                if (write->header.sector_num <= bgd.block_bitmap_sector_end &&
                    write->header.sector_num >= bgd.block_bitmap_sector_start)
                    return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP;

                if (write->header.sector_num <= bgd.inode_bitmap_sector_end &&
                    write->header.sector_num >= bgd.inode_bitmap_sector_start)
                    return SECTOR_EXT2_BLOCK_GROUP_INODEMAP;

                if (write->header.sector_num <= bgd.inode_table_sector_end &&
                    write->header.sector_num >= bgd.inode_table_sector_start)
                    return SECTOR_EXT2_INODE;

                if (write->header.sector_num <= bgd_end &&
                    write->header.sector_num >= bgd_start)
                    return SECTOR_EXT2_DATA;

            }

            return SECTOR_EXT2_PARTITION;
        }
    }

   return SECTOR_UNKNOWN;
}*/

int __deserialize_mbr(FILE* index, struct bson_info* bson, struct mbr* mbr,
                      struct kv_store* store)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "gpt") != 0)
        return EXIT_FAILURE;

    mbr->gpt = (uint8_t*)value1.data;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    mbr->sector = *((uint32_t*)value1.data);
    redis_hash_field_set(store, REDIS_MBR_SECTOR_INSERT,
                         mbr->sector, "gpt", ((uint8_t*) &(mbr->gpt)),
                         sizeof(bool));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "active_partitions") != 0)
        return EXIT_FAILURE;

    mbr->active_partitions = *((uint32_t*)value1.data);
    redis_hash_field_set(store, REDIS_MBR_SECTOR_INSERT,
                         mbr->sector, "partitions", ((uint8_t*)value1.data),
                         sizeof(uint32_t));
    return EXIT_SUCCESS;
}

int __deserialize_partition(FILE* index, struct bson_info* bson,
                            struct kv_store* store)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "pte_num") != 0)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "partition_type") != 0)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "first_sector_lba") != 0)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "final_sector_lba") != 0)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int __deserialize_ext4_fs(FILE* index, struct bson_info* bson,
                          struct kv_store* store)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "fs_type") != 0)
        return EXIT_FAILURE;

    if (*((uint32_t*)value1.data) != 0 &&
        *((uint32_t*)value1.data) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "mount_point") != 0)
        return EXIT_FAILURE;

    redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, 0, "mount_point", ((uint8_t*)value1.data),
                                                  strlen(value1.data) + 1);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "num_block_groups") != 0)
        return EXIT_FAILURE;

    redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, 0, "num_block_groups", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "num_files") != 0)
        return EXIT_FAILURE;

    redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, 0, "num_files", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "superblock") != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int __deserialize_ext4_bgd(FILE* index, struct bson_info* bson, uint64_t id,
                           struct kv_store* store)
{
    struct bson_kv value1, value2;
    struct ext4_bgd bgd;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "bgd") != 0)
        return EXIT_FAILURE;

    memcpy(&(bgd.bgd), value1.data, sizeof(bgd.bgd));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    bgd.sector = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "block_bitmap_sector_start") != 0)
        return EXIT_FAILURE;

    bgd.block_bitmap_sector_start = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "block_bitmap_sector_end") != 0)
        return EXIT_FAILURE;

    bgd.block_bitmap_sector_end = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_bitmap_sector_start") != 0)
        return EXIT_FAILURE;

    bgd.inode_bitmap_sector_start = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_bitmap_sector_end") != 0)
        return EXIT_FAILURE;

    bgd.inode_bitmap_sector_end = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_table_sector_start") != 0)
        return EXIT_FAILURE;

    bgd.inode_table_sector_start = *((uint32_t*)value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_table_sector_end") != 0)
        return EXIT_FAILURE;

    bgd.inode_table_sector_end = *((uint32_t*)value1.data);
    fprintf_cyan(stdout, "Storing BGD[%"PRIu64"] in Redis.\n", id);

    redis_hash_field_set(store, REDIS_BGD_SECTOR_INSERT, id,
                         "bgd", ((uint8_t*) &bgd), sizeof(bgd));
    redis_reverse_pointer_set(store, REDIS_BGDS_INSERT, bgd.sector, id);
    redis_reverse_pointer_set(store, REDIS_BGDS_SECTOR_INSERT, bgd.sector,
                                                               bgd.sector);
    return EXIT_SUCCESS;
}

int __deserialize_ext4_file(FILE* index, struct bson_info* bson,
                            uint64_t id, struct kv_store* store)
{
    struct ext4_file file;
    struct bson_kv value1, value2;
    uint64_t counter = 0;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_sector") != 0)
        return EXIT_FAILURE;

    file.inode_sector = *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_offset") != 0)
        return EXIT_FAILURE;

    file.inode_offset = *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "path") != 0)
        return EXIT_FAILURE;

    redis_hash_field_set(store, REDIS_INODE_SECTOR_INSERT, id, "path",
                                               ((uint8_t*)value1.data),
                                               strlen(value1.data) + 1);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "is_dir") != 0)
        return EXIT_FAILURE;

    file.is_dir = *((bool*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode") != 0)
        return EXIT_FAILURE;

    file.inode = *((struct ext4_inode*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sectors") != 0)
        return EXIT_FAILURE;

    bson = bson_init();
    bson->buffer = malloc(value2.size);

    if (bson->buffer == NULL)
        return EXIT_FAILURE;
    
    memcpy(bson->buffer, value2.data, value2.size);
    bson_make_readable(bson);

    /* at least 1 sector */
    if (bson_deserialize(bson, &value1, &value2) == 1)
    {
        redis_reverse_file_data_pointer_set(store, (uint64_t) *((uint32_t*)value1.data),
                                            counter, (uint64_t) counter + SECTOR_SIZE, id);
        counter += SECTOR_SIZE;
    }

    while (bson_deserialize(bson, &value1, &value2) == 1)
    {
        redis_reverse_file_data_pointer_set(store, (uint64_t) *((uint32_t*)value1.data),
                                            counter, counter + SECTOR_SIZE, id);
        counter += SECTOR_SIZE;
    }

    bson_cleanup(bson);

    redis_hash_field_set(store, REDIS_INODE_SECTOR_INSERT, id,
                         "inode", ((uint8_t*) &file), sizeof(file));
    redis_reverse_pointer_set(store, REDIS_INODES_INSERT, file.inode_sector, id);
    redis_reverse_pointer_set(store, REDIS_INODES_SECTOR_INSERT, file.inode_sector,
                                                                 file.inode_sector);
    return EXIT_SUCCESS;
}

int qemu_load_index(FILE* index, struct mbr* mbr, struct kv_store* store)
{
    uint64_t i, j, counter = 0;
    uint32_t num_block_groups, num_files;
    size_t len;
    struct bson_info* bson;

    bson = bson_init();

    /* mbr */
    if (__deserialize_mbr(index, bson, mbr, store))
    {
        fprintf_light_red(stderr, "Error loading MBR document.\n");
        return EXIT_FAILURE;
    }

    fprintf_yellow(stdout, "Deserializing %"PRIu64" partitions.\n",
                            mbr->active_partitions);

    /* partition entries */
    for (i = 0; i < mbr->active_partitions; i++)
    {
        fprintf_light_cyan(stdout, "Partition loop.\n");
        if (__deserialize_partition(index, bson, store))
        {
            fprintf_light_red(stderr, "Error loading partition document.\n");
            return EXIT_FAILURE;
        }


        if (__deserialize_ext4_fs(index, bson, store))
        {
            fprintf_light_red(stderr, "Error loading ext4_fs document.\n");
            return EXIT_FAILURE;
        }

        len = sizeof(num_block_groups);

        if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET, 0, "num_block_groups",
                           (uint8_t*) &num_block_groups, &len))
        {
            fprintf_light_red(stderr, "Error retrieving num_block_groups "
                                      "from Redis.\n");
            return EXIT_FAILURE;
        }

        for (j = 0; j < num_block_groups; j++)
        {
            if (__deserialize_ext4_bgd(index, bson, j, store))
            {
                fprintf_light_red(stderr, "Error loading ext4_bgd document."
                                          "\n");
                return EXIT_FAILURE;
            }
        }   

        len = sizeof(num_files);
        
        if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET, 0, "num_files",
                           (uint8_t*) &num_files, &len))
        {
            fprintf_light_red(stderr, "Error retrieving num_files "
                                      "from Redis.\n");
            return EXIT_FAILURE;
        }

        for (j = 0; j < num_files; j++)
        {

            if (__deserialize_ext4_file(index, bson, j, store))
            {
                fprintf_light_red(stderr, "Error loading ext4_file document."
                                          "\n");
                fprintf_light_red(stderr, "Assuming early termination of "
                                          "file records.\n");
                break;
            }
        }

        redis_set_fcounter(store, j+1);

        redis_flush_pipeline(store);
    } 

    bson_cleanup(bson);

    return EXIT_SUCCESS;
}
