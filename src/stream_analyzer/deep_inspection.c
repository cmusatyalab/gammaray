#define _GNU_SOURCE
#include "color.h"
#include "util.h"
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

void print_mbr(struct mbr* mbr)
{
    fprintf_light_cyan(stdout, "-- MBR --\n");
    fprintf_yellow(stdout, "mbr->gpt == %d\n", mbr->gpt);
    fprintf_yellow(stdout, "mbr->sector == %"PRIu64"\n", mbr->sector);
    fprintf_yellow(stdout, "mbr->active_partitions == %"PRIu64"\n",
                            mbr->active_partitions);
}

int qemu_print_sector_type(enum SECTOR_TYPE type)
{
    switch(type)
    {
        case SECTOR_MBR:
            fprintf_light_green(stdout, "Write to MBR detected.\n");
            return 0;
        case SECTOR_EXT2_SUPERBLOCK:
            fprintf_light_green(stdout, "Write to ext4 superblock "
                                        "detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR:
            fprintf_light_green(stdout, "Write to ext4 block group descriptor"
                                        " detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP:
            fprintf_light_green(stdout, "Write to ext4 block group block map"
                                        " detected.\n");
            return 0;
        case SECTOR_EXT2_BLOCK_GROUP_INODEMAP:
            fprintf_light_green(stdout, "Write to ext4 block group inode map"
                                        " detected.\n");
            return 0;
        case SECTOR_EXT2_INODE:
            fprintf_light_green(stdout, "Write to ext4 inode detected.\n");
            return 0;
        case SECTOR_EXT2_DATA:
            fprintf_light_green(stdout, "Write to ext4 data block "
                                        "detected.\n");
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

int __emit_field_update(struct kv_store* store, char* field, char* type,
                        char* channel, enum BSON_TYPE bson_type, void* oldv,
                        void* newv, uint64_t oldv_size, uint64_t newv_size, 
                        uint64_t transaction_id)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;

    if (bson == NULL)
    {
        fprintf_light_red(stderr, "Failed creating BSON handle. OOM?\n");
        return EXIT_FAILURE;
    }

    val.type = BSON_STRING;
    val.size = strlen(type);
    val.key = "type";
    val.data = type;

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "transaction";
    val.data = &(transaction_id);

    bson_serialize(bson, &val);

    val.type = bson_type;
    val.key = "old";
    val.data = &(oldv);
    val.size = oldv_size;

    bson_serialize(bson, &val);

    val.type = bson_type;
    val.key = "new";
    val.data = &(newv);
    val.size = newv_size;

    bson_serialize(bson, &val);

    bson_finalize(bson);

    if (redis_publish(store, channel, bson->buffer, bson->position))
    {
        fprintf_light_red(stderr, "Failure publishing "
                                  "Redis message.\n");
        return EXIT_FAILURE;
    }

    bson_cleanup(bson);
    return EXIT_SUCCESS;
}
{
    fprintf_light_white(stdout, "__emit_file_bytes()\n");
    return EXIT_SUCCESS;
}

int __diff_superblock(struct qemu_bdrv_write* write, struct kv_store* store, 
                      const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_superblock()\n");
    return EXIT_SUCCESS;
}

int __diff_mbr(struct qemu_bdrv_write* write, struct kv_store* store,
               const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_mbr()\n");
    return EXIT_SUCCESS;
}

int __diff_bgds(struct qemu_bdrv_write* write, struct kv_store* store,
                const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_bgds()\n");
    return EXIT_SUCCESS;
}

int __diff_inodes(struct qemu_bdrv_write* write, struct kv_store* store,
                  const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_inodes()\n");
    return EXIT_SUCCESS;
}

int __diff_bitmap(struct qemu_bdrv_write* write, struct kv_store* store,
                  const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_bitmap()\n");
    return EXIT_SUCCESS;
}

int __diff_extent_tree(struct qemu_bdrv_write* write, struct kv_store* store,
                       const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_extent_tree()\n");
    return EXIT_SUCCESS;
}

int __qemu_dispatch_write(struct qemu_bdrv_write* write,
                          struct kv_store* store, const char* vmname,
                          const char* pointer)
{
    if (strncmp(pointer, "start", strlen("start")) == 0)
        __emit_file_bytes(write, store, vmname, pointer);
    else if(strncmp(pointer, "fs", strlen("fs")) == 0)
        __diff_superblock(write, store, vmname, pointer);
    else if(strncmp(pointer, "mbr", strlen("mbr")) == 0)
        __diff_mbr(write, store, vmname, pointer);
    else if(strncmp(pointer, "lbgds", strlen("lbgds")) == 0)
        __diff_bgds(write, store, vmname, pointer);
    else if(strncmp(pointer, "lfiles", strlen("lfiles")) == 0)
        __diff_inodes(write, store, vmname, pointer);
    else if(strncmp(pointer, "bgd", strlen("bgd")) == 0)
        __diff_bitmap(write, store, vmname, pointer);
    else if(strncmp(pointer, "lextents", strlen("lextents")) == 0)
        __diff_extent_tree(write, store, vmname, pointer);
    else
    {
        fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                      pointer);
        exit(1);
    }
    return EXIT_SUCCESS;
}

int qemu_deep_inspect(struct ext4_superblock* superblock,
                      struct qemu_bdrv_write* write, struct kv_store* store,
                      const char* vmname)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t block_size = ext4_block_size(*superblock);

    fprintf_light_cyan(stdout, "block_size: %"PRIu64"\n", block_size);
    fprintf_light_cyan(stdout, "block_size / SECTOR_SIZE: %"PRIu64"\n", block_size / SECTOR_SIZE);

    for (i = 0; i < write->header.nb_sectors; i += block_size / SECTOR_SIZE)
    {
        fprintf_light_yellow(stdout, "i: %"PRIu64"\n", i);
        if (redis_sector_lookup(store, write->header.sector_num + i,
            result, &len))
        {
            fprintf_light_red(stderr, "Error doing sector lookup.\n");
            redis_enqueue_pipelined(store, write->header.sector_num + i,
                                               &(write->data[i*SECTOR_SIZE]),
                                               SECTOR_SIZE);
            continue;
        } 

        if (len)
        {
            result[len] = 0;
            __qemu_dispatch_write(write, store, vmname, (const char*) result);
        }
        else
        {
            fprintf_light_red(stderr, "Returned sector lookup empty.\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int qemu_get_superblock(struct kv_store* store,
                        struct ext4_superblock* superblock,
                        uint64_t fs_id)
{
    size_t len = sizeof(struct ext4_superblock);

    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET,
                             fs_id, "superblock", (uint8_t*) superblock,
                             &len))
    {
        fprintf_light_red(stderr, "Error retrieving superblock\n");
        return EXIT_FAILURE;
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
    else if(strncmp(str, "fs", strlen("fs")) == 0)
        return SECTOR_EXT2_SUPERBLOCK;
    else if(strncmp(str, "mbr", strlen("mbr")) == 0)
        return SECTOR_MBR;
    else if(strncmp(str, "lbgds", strlen("lbgds")) == 0)
        return SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR;
    else if(strncmp(str, "lfiles", strlen("lfiles")) == 0)
        return SECTOR_EXT2_INODE;
    else if(strncmp(str, "bgd", strlen("bgd")) == 0)
        return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP |
               SECTOR_EXT2_BLOCK_GROUP_INODEMAP;
    else if(strncmp(str, "lextents", strlen("lextents")) == 0)
        return SECTOR_EXT4_EXTENT;
    fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                    str);
    return SECTOR_UNKNOWN;
}

enum SECTOR_TYPE qemu_infer_sector_type(struct ext4_superblock* super,
                                        struct qemu_bdrv_write* write,
                                        struct kv_store* store)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t block_size = ext4_block_size(*super);

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
            result[len] = 0;
            return __sector_type((const char*) result);
        }
        else
        {
            return SECTOR_UNKNOWN;
        }
    }

    return SECTOR_UNKNOWN;
}

int __deserialize_mbr(struct bson_info* bson, struct kv_store* store, uint64_t id)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "sector") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_MBR_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;
        }
        else
        {
            if (redis_hash_field_set(store, REDIS_MBR_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data, (size_t) value1.size))
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int __deserialize_partition(struct bson_info* bson, struct kv_store* store,
                            uint64_t id)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "superblock_sector") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_SUPERBLOCK_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;
        }
        else
        {
            if (redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int __deserialize_fs(struct bson_info* bson, struct kv_store* store,
                     uint64_t id)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int __deserialize_bgd(struct bson_info* bson, struct kv_store* store,
                      uint64_t id)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "sector") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_BGDS_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;

            if (redis_reverse_pointer_set(store, REDIS_BGDS_SECTOR_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      (uint64_t) *((uint32_t *) value1.data)))
                return EXIT_FAILURE;
        }
        else
        {
            if (redis_hash_field_set(store, REDIS_BGD_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int __deserialize_file(struct bson_info* bson, struct kv_store* store,
                       uint64_t id)
{
    struct bson_info* bson2;
    struct bson_kv value1, value2;

    uint64_t counter = 0, sector = 0;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "inode_sector") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_INODES_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;

            if (redis_reverse_pointer_set(store, REDIS_INODES_SECTOR_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      (uint64_t) *((uint32_t *) value1.data)))
                return EXIT_FAILURE;
        }
        else if (strcmp(value1.key, "data") == 0)
        {
            bson2 = bson_init();
            free(bson2->buffer);
            bson2->buffer = malloc(value2.size);

            if (bson2->buffer == NULL)
                return EXIT_FAILURE;
            
            memcpy(bson2->buffer, value2.data, value2.size);
            bson_make_readable(bson2);

            while (bson_deserialize(bson2, &value1, &value2) == 1)
            {
                sscanf((const char*) value1.key, "%"SCNu64, &sector);

                if (redis_hash_field_set(store, REDIS_DIR_SECTOR_INSERT, sector,
                                 "data", (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                {
                    free(bson2->buffer);
                    return EXIT_FAILURE;
                }

                if (redis_reverse_pointer_set(store, REDIS_DIRS_INSERT,
                                      id,
                                      sector))
                {
                    free(bson2->buffer);
                    return EXIT_FAILURE;
                }

                if (redis_reverse_pointer_set(store, REDIS_DIRS_SECTOR_INSERT,
                                      sector,
                                      id))
                {
                    free(bson2->buffer);
                    return EXIT_FAILURE;
                }
            }

            bson_cleanup(bson2);
        }
        else if (strcmp(value1.key, "sectors") == 0)
        {
            fprintf_light_red(stderr, "sectors\n");
            counter = 0;
            bson2 = bson_init();
            free(bson2->buffer);
            bson2->buffer = malloc(value2.size);

            if (bson2->buffer == NULL)
            {
                free(bson2->buffer);
                return EXIT_FAILURE;
            }
            
            memcpy(bson2->buffer, value2.data, (size_t) value2.size);
            bson_make_readable(bson2);

            while (bson_deserialize(bson2, &value1, &value2) == 1)
            {
                redis_reverse_file_data_pointer_set(store, (uint64_t) *((uint32_t*)value1.data),
                                                    counter, counter + SECTOR_SIZE, id);
                counter += SECTOR_SIZE;
            }

            bson_cleanup(bson2);
        }
        else if (strcmp(value1.key, "extents") == 0)
        {
            bson2 = bson_init();
            free(bson2->buffer);
            bson2->buffer = malloc(value2.size);

            if (bson2->buffer == NULL)
                return EXIT_FAILURE;

            memcpy(bson2->buffer, (uint8_t *)value2.data, (size_t) value2.size);
            bson_make_readable(bson2);

            while (bson_deserialize(bson2, &value1, &value2) == 1)
            {
                sscanf((const char*) value1.data, "%"SCNu64, &sector);

                if (redis_hash_field_set(store, REDIS_EXTENT_SECTOR_INSERT, sector,
                                 "data", (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }

                if (redis_reverse_pointer_set(store, REDIS_EXTENTS_INSERT,
                                      id,
                                      sector))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }

                if (redis_reverse_pointer_set(store, REDIS_EXTENTS_SECTOR_INSERT,
                                      sector,
                                      id))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }
            }

            bson_cleanup(bson2);
        }
        else
        {
            if (redis_hash_field_set(store, REDIS_INODE_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int qemu_load_index(FILE* index, struct kv_store* store)
{
    struct bson_kv value1, value2;
    struct bson_info* bson = bson_init();
    uint64_t fs_id = 0;
    uint64_t bgd_counter = 0;
    uint64_t file_counter = 0;

    while (bson_readf(bson, index) == 1)
    {
        if (bson_deserialize(bson, &value1, &value2) != 1)
            return EXIT_FAILURE;
        
        if (strcmp(value1.key, "type") != 0)
        {
            fprintf_light_red(stderr, "Document missing 'type' field.\n");
            return EXIT_FAILURE;
        }

        if (strcmp(value1.data, "file") == 0)
        {
            __deserialize_file(bson, store, file_counter++);
        }
        else if (strcmp(value1.data, "bgd") == 0)
        {
            __deserialize_bgd(bson, store, bgd_counter++);
        }
        else if (strcmp(value1.data, "fs") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a fs record --\n");

            if (bson_deserialize(bson, &value1, &value2) != 1)
                return EXIT_FAILURE;
            
            if (strcmp(value1.key, "pte_num") != 0)
            {
                fprintf_light_red(stderr, "fs missing 'pte_num' "
                                          "field.\n");
                return EXIT_FAILURE;
            }

            fs_id = (uint64_t) *((uint32_t*) value1.data);
            __deserialize_fs(bson, store, fs_id);
        }
        else if (strcmp(value1.data, "partition") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a partition "
                                         "record --\n");
            if (bson_deserialize(bson, &value1, &value2) != 1)
                return EXIT_FAILURE;
            
            if (strcmp(value1.key, "pte_num") != 0)
            {
                fprintf_light_red(stderr, "Partition missing 'pte_num' "
                                          "field.\n");
                return EXIT_FAILURE;
            }

            fs_id = (uint64_t) *((uint32_t*) value1.data);
            __deserialize_partition(bson, store, fs_id);

        }
        else if (strcmp(value1.data, "mbr") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a mbr record --\n");
            if (__deserialize_mbr(bson, store, (uint64_t) 0))
                return EXIT_FAILURE;
        }
        else
        {
            fprintf_light_red(stderr, "Unhandled type: %s\n", value1.data);
            return EXIT_FAILURE;
        }
    }

    fprintf_light_yellow(stdout, "-- Deserialized %"PRIu64" bgd's --\n",
                                 bgd_counter);

    fprintf_light_yellow(stdout, "-- Deserialized %"PRIu64" file's --\n",
                                 file_counter);

    bson_cleanup(bson);
    redis_set_fcounter(store, file_counter);
    redis_flush_pipeline(store);

    return EXIT_SUCCESS;
}
