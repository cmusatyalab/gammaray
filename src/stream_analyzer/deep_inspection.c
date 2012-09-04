#define _GNU_SOURCE
#include "color.h"
#include "deep_inspection.h"
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

int qemu_deep_inspect(struct qemu_bdrv_write* write, struct mbr* mbr,
                      struct kv_store* store, char* vmname)
{
    uint64_t i, j, start = 0, end = 0;
    uint64_t inode_offset;
    char* channel_name;
    struct partition* partition;
    struct ext2_fs* fs;
    struct ext2_file* file;
    struct ext2_inode new_inode;
    struct bson_info* bson;
    struct bson_kv val;

    for (i = 0; i < linkedlist_size(mbr->pt); i++)
    {
        partition = linkedlist_get(mbr->pt, i);
        
        if (write->header.sector_num <= partition->final_sector_lba &&
            write->header.sector_num >= partition->first_sector_lba)
        {
            fs = &(partition->fs);
            for (j = 0; j < linkedlist_size(fs->ext2_files); j++)
            {
                file = linkedlist_get(fs->ext2_files, j);

                if (file->inode_sector >= write->header.sector_num &&
                    file->inode_sector <= write->header.sector_num +
                                          write->header.nb_sectors - 1)
                {
                    fprintf_light_red(stdout, "Write to sector %"PRIu64
                                              " containing inode for file "
                                              "%s\n", file->inode_sector,
                                              file->path);

                    inode_offset = (file->inode_sector -
                                    write->header.sector_num) * 512;
                    inode_offset += file->inode_offset;

                    new_inode = *((struct ext2_inode*)
                                  &(write->data[inode_offset]));

                    /* compare inode, emit diff */
                    ext2_compare_inodes(&(file->inode), &new_inode, store,
                                        vmname, file->path);
                    return SECTOR_EXT2_PARTITION;
                }

                if (bst_find(file->sectors, write->header.sector_num))
                {
                    fprintf_light_red(stdout, "Write to sector %"PRId64
                                              " modifying %s\n",
                                              write->header.sector_num,
                                              file->path);
                    if (file->is_dir)
                    {
                        fprintf_light_green(stdout, "Directory modification."
                                                    "\n");
                        return SECTOR_EXT2_PARTITION;
                    }

                    if (!file->is_dir)
                    {
                        bson = bson_init();

                        val.type = BSON_STRING;
                        val.size = strlen(FILE_DATA_WRITE); 
                        val.key = "type";
                        val.data = FILE_DATA_WRITE;

                        bson_serialize(bson, &val);

                        val.type = BSON_INT64;
                        val.key = "start_byte";
                        val.data = &start;

                        bson_serialize(bson, &val);

                        val.type = BSON_INT64;
                        val.key = "end_byte";
                        val.data = &end;

                        bson_serialize(bson, &val);

                        val.type = BSON_BINARY;
                        val.subtype = BSON_BINARY_GENERIC;
                        val.key = "data";
                        val.data = write->data;
                        val.size = write->header.nb_sectors * SECTOR_SIZE;

                        bson_serialize(bson, &val);
                        bson_finalize(bson);

                        channel_name = construct_channel_name(vmname,
                                                              file->path);

                        if (redis_publish(store, channel_name, bson->buffer,
                                          bson->position))
                        {
                            fprintf_light_red(stderr, "Failure publishing "
                                                      "Redis message.\n");
                            return -1;
                        }

                        free(channel_name);
                        bson_reset(bson);
                        return SECTOR_EXT2_PARTITION;
                    } /* is not dir */
                } /* if is in file */
            } /* loop on files */
        } /* if in partition */
    } /* loop on partitions */

    /* handling unknown write, send to queue */
    for (i = 0; i < write->header.nb_sectors; i++)
    {
        redis_enqueue_pipelined(store, write->header.sector_num + i,
                                       &(write->data[i*SECTOR_SIZE]),
                                       SECTOR_SIZE);
    }
    redis_flush_pipeline(store);
   return 0;
}

int qemu_infer_sector_type(struct qemu_bdrv_write* write, struct mbr* mbr)
{
    uint64_t i, j;
    struct partition* partition;
    struct ext2_fs* fs;
    struct ext2_bgd* bgd;

    uint64_t block_size, blocks_per_block_group, sectors_per_block_group,
             start_sector, bgd_start, bgd_end;

    if (write->header.sector_num == mbr->sector)
        return SECTOR_MBR;

    for (i = 0; i < linkedlist_size(mbr->pt); i++)
    {
        partition = linkedlist_get(mbr->pt, i);
        
        if (write->header.sector_num <= partition->final_sector_lba &&
            write->header.sector_num >= partition->first_sector_lba)
        {
            if (write->header.sector_num == partition->first_sector_lba + 2)
                return SECTOR_EXT2_SUPERBLOCK;

            fs = &(partition->fs);
            block_size = ext2_block_size(fs->superblock);
            blocks_per_block_group = fs->superblock.s_blocks_per_group;
            sectors_per_block_group = blocks_per_block_group *
                                      (block_size / SECTOR_SIZE);
            start_sector = fs->superblock.s_first_data_block *
                           (block_size / SECTOR_SIZE) +
                           partition->first_sector_lba;

            for (j = 0; j < linkedlist_size(fs->ext2_bgds); j++)
            {
                bgd_start = start_sector + sectors_per_block_group * j;
                bgd_end = bgd_start + sectors_per_block_group - 1;
                bgd = linkedlist_get(fs->ext2_bgds, j);
                if (write->header.sector_num == bgd->sector)
                    return SECTOR_EXT2_BLOCK_GROUP_DESCRIPTOR;

                if (write->header.sector_num <= bgd->block_bitmap_sector_end &&
                    write->header.sector_num >= bgd->block_bitmap_sector_start)
                    return SECTOR_EXT2_BLOCK_GROUP_BLOCKMAP;

                if (write->header.sector_num <= bgd->inode_bitmap_sector_end &&
                    write->header.sector_num >= bgd->inode_bitmap_sector_start)
                    return SECTOR_EXT2_BLOCK_GROUP_INODEMAP;

                if (write->header.sector_num <= bgd->inode_table_sector_end &&
                    write->header.sector_num >= bgd->inode_table_sector_start)
                    return SECTOR_EXT2_INODE;

                if (write->header.sector_num <= bgd_end &&
                    write->header.sector_num >= bgd_start)
                    return SECTOR_EXT2_DATA;

            }

            return SECTOR_EXT2_PARTITION;
        }
    }

   return SECTOR_UNKNOWN;
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

void print_ext2_file(struct ext2_file* file)
{
    fprintf_light_cyan(stdout, "-- ext2 File --\n");
    fprintf_yellow(stdout, "file->inode_sector == %"PRIu64"\n",
                            file->inode_sector);
    fprintf_yellow(stdout, "file->inode_offset == %"PRIu64"\n",
                            file->inode_offset);
    fprintf_light_yellow(stdout, "file->path == %s\n", file->path);
    fprintf_yellow(stdout, "file->is_dir == %s\n",
                            file->is_dir ? "true" : "false");
    fprintf_yellow(stdout, "file->inode == %p\n", &(file->inode));
    if (file->sectors)
        bst_print_tree(file->sectors, 0);
    else
        fprintf_light_blue(stdout, "No sectors -- empty file\n");
}

void print_ext2_bgd(struct ext2_bgd* bgd)
{
    fprintf_light_cyan(stdout, "-- ext2 BGD --\n");
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

void print_ext2_fs(struct ext2_fs* fs)
{
    struct ext2_bgd* bgd;
    struct ext2_file* file;
    uint64_t i;

    fprintf_light_cyan(stdout, "-- ext2 FS --\n");
    fprintf_yellow(stdout, "fs->fs_type %"PRIu64"\n", fs->fs_type);
    fprintf_yellow(stdout, "fs->mount_point %s\n", fs->mount_point);
    fprintf_yellow(stdout, "fs->num_block_groups %"PRIu64"\n",
                            fs->num_block_groups);
    fprintf_yellow(stdout, "fs->num_files %"PRIu64"\n", fs->num_files);
    
    for (i = 0; i < linkedlist_size(fs->ext2_bgds); i++)
    {
        bgd = linkedlist_get(fs->ext2_bgds, i);
        print_ext2_bgd(bgd);
    }

    for (i = 0; i < linkedlist_size(fs->ext2_files); i++)
    {
        file = linkedlist_get(fs->ext2_files, i);
        print_ext2_file(file);
    }
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
        print_ext2_fs(&(pte->fs));
    }
}

void print_mbr(struct mbr* mbr)
{
    fprintf_light_cyan(stdout, "-- MBR --\n");
    fprintf_yellow(stdout, "mbr->gpt == %d\n", mbr->gpt);
    fprintf_yellow(stdout, "mbr->sector == %"PRIu64"\n", mbr->sector);
    fprintf_yellow(stdout, "mbr->active_partitions == %"PRIu64"\n",
                            mbr->active_partitions);
    fprintf_yellow(stdout, "mbr->pt == %p\n", mbr->pt);
    print_partition(mbr->pt);
}


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
    redis_hash_set(store, "mbr", 0, "gpt", ((uint8_t*)value1.data), sizeof(bool));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    mbr->sector = *((uint32_t*)value1.data);
    redis_hash_set(store, "mbr", 0, "sector", ((uint8_t*)value1.data),
                                              sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "active_partitions") != 0)
        return EXIT_FAILURE;

    mbr->active_partitions = *((uint32_t*)value1.data);
    redis_hash_set(store, "mbr", 0, "partitions", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));
    return EXIT_SUCCESS;
}

int __deserialize_partition(FILE* index, struct bson_info* bson,
                            struct kv_store* store)
{
    uint64_t pte_num;
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "pte_num") != 0)
        return EXIT_FAILURE;

    pte_num = (uint64_t) *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "partition_type") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "pte", pte_num, "partition_type", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));
    
    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "first_sector_lba") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "pte", pte_num, "first_sector_lba", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "final_sector_lba") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "pte", pte_num, "final_sector_lba", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));
    
    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "pte", pte_num, "sector", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));
    return EXIT_SUCCESS;
}

int __deserialize_ext2_fs(FILE* index, struct bson_info* bson,
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

    redis_hash_set(store, "fs", 0, "fs_type", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "mount_point") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "fs", 0, "mount_point", ((uint8_t*)value1.data),
                                                  strlen(value1.data) + 1);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "num_block_groups") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "fs", 0, "num_block_groups", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "num_files") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "fs", 0, "num_files", ((uint8_t*)value1.data),
                                                  sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "superblock") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "fs", 0, "superblock", ((uint8_t*)value1.data),
                                                  sizeof(struct ext2_superblock));

    return EXIT_SUCCESS;
}

int __deserialize_ext2_bgd(FILE* index, struct bson_info* bson, uint64_t id,
                           struct kv_store* store)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "bgd") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "bgd", ((uint8_t*)value1.data),
                                    sizeof(struct ext2_block_group_descriptor));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "sector", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "block_bitmap_sector_start") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "block_bitmap_sector_start", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "block_bitmap_sector_end") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "block_bitmap_sector_end", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_bitmap_sector_start") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "inode_bitmap_sector_start", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_bitmap_sector_end") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "inode_bitmap_sector_end", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_table_sector_start") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "inode_table_sector_start", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_table_sector_end") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "bgd", id, "inode_table_sector_end", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    return EXIT_SUCCESS;
}

int __deserialize_ext2_file(FILE* index, struct bson_info* bson,
                            uint64_t id, struct kv_store* store)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_sector") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "file", id, "inode_sector", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode_offset") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "file", id, "inode_offset", ((uint8_t*)value1.data),
                                               sizeof(uint32_t));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "path") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "file", id, "path", ((uint8_t*)value1.data),
                                               strlen(value1.data) + 1);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "is_dir") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "file", id, "is_dir", ((uint8_t*)value1.data),
                                               sizeof(bool));

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "inode") != 0)
        return EXIT_FAILURE;

    redis_hash_set(store, "file", id, "inode", ((uint8_t*)value1.data),
                                               sizeof(struct ext2_inode));

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
        redis_add_sector_map(store, (uint64_t) *((uint32_t*)value1.data), id);
    }

    while (bson_deserialize(bson, &value1, &value2) == 1)
    {
        redis_add_sector_map(store, (uint64_t) *((uint32_t*)value1.data), id);
    }

    bson_cleanup(bson);

    return EXIT_SUCCESS;
}

int qemu_load_index(FILE* index, struct mbr* mbr, struct kv_store* store)
{
    uint64_t i, j;
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


        if (__deserialize_ext2_fs(index, bson, store))
        {
            fprintf_light_red(stderr, "Error loading ext2_fs document.\n");
            return EXIT_FAILURE;
        }

        len = sizeof(num_block_groups);

        if (redis_hash_get(store, "fs", i, "num_block_groups",
                           (uint8_t*) &num_block_groups, &len))
        {
            fprintf_light_red(stderr, "Error retrieving num_block_groups "
                                      "from Redis.\n");
            return EXIT_FAILURE;
        }

        for (j = 0; j < num_block_groups; j++)
        {
            if (__deserialize_ext2_bgd(index, bson, i, store))
            {
                fprintf_light_red(stderr, "Error loading ext2_bgd document."
                                          "\n");
                return EXIT_FAILURE;
            }
        }   

        len = sizeof(num_files);
        
        if (redis_hash_get(store, "fs", i, "num_files",
                           (uint8_t*) &num_files, &len))
        {
            fprintf_light_red(stderr, "Error retrieving num_files "
                                      "from Redis.\n");
            return EXIT_FAILURE;
        }

        for (j = 0; j < num_files; j++)
        {
            if (__deserialize_ext2_file(index, bson, j, store))
            {
                fprintf_light_red(stderr, "Error loading ext2_file document."
                                          "\n");
                fprintf_light_red(stderr, "Assuming early termination of "
                                          "file records.\n");
                break;
            }
        }

        redis_flush_pipeline(store);
    } 

    bson_cleanup(bson);

    return EXIT_SUCCESS;
}
