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

#define FIELD_COMPARE(field, fname, type, btype) {\
    if (old->field != new->field) \
        __emit_field_update(store, fname, type, channel, btype, \
                            &(old->field), &(new->field), sizeof(old->field), \
                            sizeof(new->field), write_counter, true, false); }

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#define D_PRINT64(val) { fprintf_light_yellow(stdout, "" \
                         STRINGIFY(val)" : %"PRIu64"\n", val); }
#define D_PRINT16(val) { fprintf_light_yellow(stdout, "" \
                         STRINGIFY(val)" : %"PRIu32"\n", (uint32_t) val); }

/*** Pre-Definitions ***/
int qemu_deep_inspect(struct ext4_superblock* superblock,
                      struct qemu_bdrv_write* write,
                      struct kv_store* store, uint64_t write_counter,
                      char* vmname, uint64_t partition_offset);

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
            return 0;
        case SECTOR_UNKNOWN:
            fprintf_light_red(stdout, "Unknown sector type.\n");
    }

    return -1;
}

int __emit_deleted_file(struct kv_store* store,  char* channel,
                        char* file, size_t flen, uint64_t transaction_id)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;

    fprintf_light_blue(stdout, "DELETE[%.*s] in channel %s.\n", flen, file, 
                                                                channel);

    if (bson == NULL)
    {
        fprintf_light_red(stderr, "Failed creating BSON handle. OOM?\n");
        return EXIT_FAILURE;
    }

    val.type = BSON_STRING;
    val.size = strlen("mutation");
    val.key = "type";
    val.data = "mutation";

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "transaction";
    val.data = &(transaction_id);

    bson_serialize(bson, &val);

    val.type = BSON_STRING;
    val.size = flen;
    val.key = "delete";
    val.data = file;

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

int __emit_created_file(struct kv_store* store,  char* channel,
                        char* file, size_t flen, uint64_t transaction_id)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;

    fprintf_light_blue(stdout, "CREATE[%.*s] in channel %s.\n", flen, file, channel);

    if (bson == NULL)
    {
        fprintf_light_red(stderr, "Failed creating BSON handle. OOM?\n");
        return EXIT_FAILURE;
    }

    val.type = BSON_STRING;
    val.size = strlen("mutation");
    val.key = "type";
    val.data = "mutation";

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "transaction";
    val.data = &(transaction_id);

    bson_serialize(bson, &val);

    val.type = BSON_STRING;
    val.size = flen;
    val.key = "create";
    val.data = file;

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

int __emit_rename_file(struct kv_store* store,  char* channel,
                       char* file, size_t flen, uint64_t transaction_id)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;

    fprintf_light_blue(stdout, "CREATE[%.*s] in channel %s.\n", flen, file, channel);

    if (bson == NULL)
    {
        fprintf_light_red(stderr, "Failed creating BSON handle. OOM?\n");
        return EXIT_FAILURE;
    }

    val.type = BSON_STRING;
    val.size = strlen("mutation");
    val.key = "type";
    val.data = "mutation";

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "transaction";
    val.data = &(transaction_id);

    bson_serialize(bson, &val);

    val.type = BSON_STRING;
    val.size = flen;
    val.key = "rename";
    val.data = file;

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

int __emit_field_update(struct kv_store* store, char* field, char* type,
                        char* channel, enum BSON_TYPE bson_type, void* oldv,
                        void* newv, uint64_t oldv_size, uint64_t newv_size, 
                        uint64_t transaction_id, bool emit, bool print)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;

    if (print)
    {
        fprintf_light_red(stdout, "Field '%s' differs.\n", field);

        fprintf_light_magenta(stdout, "old:\t");
        hexdump(oldv, oldv_size);
        fprintf_light_magenta(stdout, "new:\t");
        hexdump(newv, newv_size);
    }

    if (bson == NULL)
    {
        fprintf_light_red(stderr, "Failed creating BSON handle. OOM?\n");
        return EXIT_FAILURE;
    }

    if (emit)
    {
        val.type = BSON_STRING;
        val.size = strlen(type);
        val.key = "type";
        val.data = type;

        bson_serialize(bson, &val);

        val.type = BSON_INT64;
        val.key = "transaction";
        val.data = &(transaction_id);

        bson_serialize(bson, &val);

        val.type = BSON_STRING;
        val.size = strlen(field);
        val.key = "field";
        val.data = field;

        bson_serialize(bson, &val);

        val.type = bson_type;
        val.subtype = BSON_BINARY_GENERIC;
        val.key = "old";
        val.data = oldv;
        val.size = oldv_size;

        bson_serialize(bson, &val);

        val.type = bson_type;
        val.subtype = BSON_BINARY_GENERIC;
        val.key = "new";
        val.data = newv;
        val.size = newv_size;

        bson_serialize(bson, &val);

        bson_finalize(bson);

        if (redis_publish(store, channel, bson->buffer, bson->position))
        {
            fprintf_light_red(stderr, "Failure publishing "
                                      "Redis message.\n");
            return EXIT_FAILURE;
        }
    }

    bson_cleanup(bson);
    return EXIT_SUCCESS;
}

int __reinspect_write(struct ext4_superblock* super, struct kv_store* store,
                      int64_t partition_offset, uint64_t sector,
                      uint64_t write_counter, char* vmname)
{
    uint8_t buf[ext4_block_size(*super)];
    size_t len = ext4_block_size(*super);
    struct qemu_bdrv_write write;

    write.header.nb_sectors = len / SECTOR_SIZE;
    write.header.sector_num = sector;
    write.data = buf;

    if (redis_dequeue(store, sector, buf, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving queued write [%"
                                  PRIu64"]\n", sector);
        return EXIT_FAILURE;
    }

    if (len == 0)
    {
        fprintf_light_red(stderr, "Empty write returned for [%"PRIu64"]\n",
                                  sector);
        return EXIT_FAILURE;
    }

    fprintf_light_blue(stdout, "DEQUEUED!\n");
    hexdump(buf, len);

    return qemu_deep_inspect(super, &write, store, write_counter, vmname,
                             partition_offset);
}

uint64_t __inode_sector(struct kv_store* store, struct ext4_superblock* super,
                        uint64_t inode)
{
    uint64_t block_group = (inode - 1) / super->s_inodes_per_group;
    uint64_t inode_table_sector;
    uint64_t inode_sector;
    uint64_t inode_offset = (inode - 1) % super->s_inodes_per_group;
    D_PRINT64(inode_offset);
    inode_offset *= super->s_inode_size;
    D_PRINT64(inode_offset);
    size_t len = sizeof(inode_table_sector);
    fprintf_light_red(stdout, "__inode_sector\n");

    if (redis_hash_field_get(store, REDIS_BGD_SECTOR_GET, block_group,
                             "inode_table_sector_start",
                             (uint8_t*) &inode_table_sector,
                             &len))
    {
        fprintf_light_red(stderr, "Failed loading inode_table_sector_start"
                                  " for BGD:%"PRIu64"\n", block_group);
        return EXIT_FAILURE;
    }

    D_PRINT64(super->s_inodes_per_group);
    D_PRINT64(inode);
    D_PRINT64(block_group);
    D_PRINT64(inode_offset);
    D_PRINT64(inode_table_sector);
    
    inode_sector = (inode_table_sector * SECTOR_SIZE +
                    inode_offset) / SECTOR_SIZE;

    fprintf_light_white(stdout, "inode_sector: %"PRIu64"\n", inode_sector);
  
    return inode_sector;
}

uint64_t __inode_offset(struct kv_store* store, struct ext4_superblock* super,
                        uint64_t inode)
{
    uint64_t block_group = (inode - 1) / super->s_inodes_per_group;
    uint64_t inode_table_sector;
    uint64_t inode_offset = (inode - 1) % super->s_inodes_per_group;
    D_PRINT64(inode_offset);
    inode_offset *= super->s_inode_size;
    D_PRINT64(inode_offset);
    size_t len = sizeof(inode_table_sector);
    fprintf_light_red(stdout, "__inode_offset\n");

    if (redis_hash_field_get(store, REDIS_BGD_SECTOR_GET, block_group,
                             "inode_table_sector_start",
                             (uint8_t*) &inode_table_sector,
                             &len))
    {
        fprintf_light_red(stderr, "Failed loading inode_table_sector_start"
                                  " for BGD:%"PRIu64"\n", block_group);
        return EXIT_FAILURE;
    }

    inode_offset += inode_table_sector * SECTOR_SIZE;
    inode_offset %= SECTOR_SIZE;

    D_PRINT64(super->s_inodes_per_group);
    D_PRINT64(inode);
    D_PRINT64(block_group);
    D_PRINT64(inode_offset);
    D_PRINT64(inode_table_sector);

    return inode_offset;
}
/*
int __dentry_rename()
{
    char deleted_copy[4096], created_copy[4096];
    char* channel;

    fprintf_light_cyan(stdout, "Rename: %.*s -> %.*s\n",
                       old->name, old->name_len,
                       new->name, new->name_len);

    channel = construct_channel_name(vmname, deleted_copy);
    __emit_rename_file(store, channel, (char*) new->name,
                       new->name_len, write_counter);
    free(channel);

    channel = construct_channel_name(vmname, created_copy);
    __emit_created_file(store, channel, (char*) new->name,
                       new->name_len, write_counter);
    free(channel);
    channel = NULL;
}*/

int __diff_dir(uint8_t* write, struct kv_store* store, 
               char* vmname, uint64_t write_counter,
               char* pointer, size_t write_len, struct ext4_superblock* super,
               uint64_t partition_offset)
{
    uint64_t dir = 0, old_pos = 0, new_pos = 0, file = 0;
    struct ext4_dir_entry* old, *new;
    struct ext4_dir_entry cleared = {   .inode = 0,
                                        .rec_len = 0,
                                        .name_len = 0,
                                        .file_type = 0,
                                        .name = {0}
                                    };
    char old_path[4096]; // new_path[4096];
    uint8_t old_dir[ext4_block_size(*super)];
    size_t len;//, len2;
    //char* channel = NULL;
    //uint8_t** files;
    //`bool found;

    /**** LOAD DIR DATA ****/
    fprintf_light_white(stdout, "__diff_dir(), write_len == %zu\n", write_len);
    fprintf_light_white(stdout, "operating on: %s\n", pointer);

    strtok(pointer, ":");
    pointer = strtok(NULL, ":");

    if (pointer == NULL)
    {
        fprintf_light_red(stderr, "Failed parsing dir pointer.\n");
        return EXIT_FAILURE;
    }

    sscanf(pointer, "%"PRIu64, &dir);
    fprintf_light_white(stdout, "Loading data for dir %"PRIu64"\n", dir);

    /**** DIR DATA ****/
    if (redis_hash_field_get(store, REDIS_DIR_SECTOR_GET, dir, "data",
                             old_dir, &write_len))
    {
        fprintf_light_red(stderr, "Failed retrieving data for dirdata:%"
                                  PRIu64"\n", dir);
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "loaded: %zu bytes.\n", write_len);

    /**** FILE POINTER ****/
    len = sizeof(file);
    if (redis_hash_field_get(store, REDIS_DIR_SECTOR_GET, dir, "file",
                             (uint8_t*) &file, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving file for dirdata:%"
                                  PRIu64"\n", dir);
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "Loading path for file %"PRIu64"\n", file);

    /**** PATH INFORMATION ****/
    len = 4096;
    if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "path",
                             (uint8_t*) old_path, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving path for file:%"
                                  PRIu64"\n", file);
        return EXIT_FAILURE;
    }

    old_path[len] = '\0';
    fprintf_light_white(stdout, "Got path ['%s'] for file %"PRIu64"\n", old_path, file);

    /**** DENTRY LOOP ****/
    while (old_pos < write_len ||
           new_pos < write_len)
    {
        if (old_pos < write_len)
            old = (struct ext4_dir_entry *) &(old_dir[old_pos]);
        else
            old = &cleared; 

        if (new_pos < write_len)
            new = (struct ext4_dir_entry *) &(write[new_pos]);
        else
            new = &cleared;

        if (old->inode != new->inode)
        {
            if (old-> name_len != new->name_len ||
                strncmp((const char*) old->name,
                        (const char*) new->name,
                        (size_t) new->name_len) != 0)
            {
                /* Could be a NEW file, and/or DELETED file */
                /* add to sets, check at end */

                // __dentry_new();
                // __dentry_rm();
            }
            else /* inode swap; metadata change only */
            {
                // __dentry_overwrite();
            }
        }
        else
        {
            if (old-> name_len != new->name_len ||
                strncmp((const char*) old->name,
                        (const char*)new->name,
                        (size_t) new->name_len) != 0)
            {
                /* RENAME file operation */

                //__dentry_rename();
            }
            /* ELSE == NOP, no change */
        }

        old_pos += old->rec_len;
        new_pos += new->rec_len;
    }

    /* check add and delete sets */
    return EXIT_SUCCESS;
}

int __diff_dir2(uint8_t* write, struct kv_store* store, 
               char* vmname, uint64_t write_counter,
               char* pointer, size_t write_len, struct ext4_superblock* super,
               uint64_t partition_offset)
{
    /* TODO:
     *       (1) deletedfset file:old if lost
     *       (2) add file:new if gained
     *       (2.5) remove from deletequeue if in it
     *       (3) update file:old sectors to point to any remaining path refs */
    uint64_t dir = 0, old_pos = 0, new_pos = 0, file = 0, inode_sector, inode_offset;
    struct ext4_dir_entry* old, *new;
    struct ext4_dir_entry cleared = {   .inode = 0,
                                        .rec_len = 0,
                                        .name_len = 0,
                                        .file_type = 0,
                                        .name = {0}
                                    };
    uint8_t old_dir[write_len];
    char path[4096];
    char created_copy[4096];
    char deleted_copy[4096];
    size_t len;
    char* channel = NULL;

    fprintf_light_white(stdout, "__diff_dir(), write_len == %zu\n", write_len);
    fprintf_light_white(stdout, "operating on: %s\n", pointer);

    strtok(pointer, ":");
    pointer = strtok(NULL, ":");

    if (pointer == NULL)
    {
        fprintf_light_red(stderr, "Failed parsing dir pointer.\n");
        return EXIT_FAILURE;
    }

    sscanf(pointer, "%"PRIu64, &dir);
    fprintf_light_white(stdout, "Loading data for dir %"PRIu64"\n", dir);

    if (redis_hash_field_get(store, REDIS_DIR_SECTOR_GET, dir, "data",
                             old_dir, &write_len))
    {
        fprintf_light_red(stderr, "Failed retrieving data for dirdata:%"
                                  PRIu64"\n", dir);
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "loaded: %zu bytes.\n", write_len);

    len = sizeof(file);
    if (redis_hash_field_get(store, REDIS_DIR_SECTOR_GET, dir, "file",
                             (uint8_t*) &file, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving file for dirdata:%"
                                  PRIu64"\n", dir);
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "Loading path for file %"PRIu64"\n", file);

    len = 4096;
    if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "path",
                             (uint8_t*) path, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving path for file:%"
                                  PRIu64"\n", file);
        return EXIT_FAILURE;
    }

    path[len] = '\0';
    fprintf_light_white(stdout, "Got path ['%s'] for file %"PRIu64"\n", path, file);

    while (old_pos < write_len || new_pos < write_len)
    {
        if (channel == NULL)
        channel = construct_channel_name(vmname, path);

        if (old_pos < write_len)
            old = (struct ext4_dir_entry *) &(old_dir[old_pos]);
        else
            old = &cleared; 

        if (new_pos < write_len)
            new = (struct ext4_dir_entry *) &(write[new_pos]);
        else
            new = &cleared;

        FIELD_COMPARE(inode, "dir.inode", "metadata", BSON_INT32); 
        FIELD_COMPARE(rec_len, "dir.rec_len", "metadata", BSON_BINARY); 
        FIELD_COMPARE(name_len, "dir.name_len", "metadata", BSON_BINARY); 
        FIELD_COMPARE(file_type, "dir.file_type", "metadata", BSON_BINARY); 

        if (strncmp((const char*) old->name, (const char*)new->name,
                    (size_t) new->name_len) != 0)
        {
            memcpy(created_copy, path, strlen(path) + 1);
            memcpy(deleted_copy, path, strlen(path) + 1);
            strncat(strcat(created_copy, "/"), (const char *)new->name,
                                                             new->name_len);
            strncat(strcat(deleted_copy, "/"), (const char *)old->name,
                                                             old->name_len);

            fprintf_light_red(stdout, "New path: %s\n", created_copy);

            if (old->inode != new->inode)
            {
                redis_get_fcounter(store, &file);
                fprintf_light_white(stdout, "Creating new file:%"
                                             PRIu64"\n", file);

                    redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT,
                                         file, "inode_num",
                                         (uint8_t*) &(new->inode), sizeof(new->inode));
                    fprintf(stdout, "set inode_num\n");

                    inode_offset = __inode_offset(store, super, new->inode);
                    redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT,
                                         file, "inode_offset",
                                         (uint8_t*) &(inode_offset), sizeof(inode_offset));
                    fprintf(stdout, "set inode_offset\n");

                    inode_sector = __inode_sector(store, super, new->inode);
                    redis_reverse_pointer_set(store, REDIS_FILES_INSERT,
                                  inode_sector,
                                  file);
                    redis_reverse_pointer_set(store, REDIS_FILES_SECTOR_INSERT,
                                  inode_sector,
                                  inode_sector);
                    fprintf(stdout, "set inode_sector\n");

                    new->file_type = ((new->file_type & 0x2) == 0x2);
                    fprintf(stdout, "new->file_type: %"PRIu32"\n", new->file_type);
                    redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT,
                                         file, "is_dir",
                                         (uint8_t*) &(new->file_type), 
                                         sizeof(new->file_type));
                    fprintf(stdout, "set is_dir\n");
                    redis_flush_pipeline(store);
                    
                    fprintf(stdout, "finished inode_sector\n");
                    //__emit_created_file(store, channel, (char*) new->name,
                    //                    new->name_len, write_counter);
                }
            }

        old_pos += old->rec_len;
        new_pos += new->rec_len;
        if (channel == NULL)
            channel = construct_channel_name(vmname, path);
    }

    if (redis_hash_field_set(store, REDIS_DIR_SECTOR_INSERT, dir, "data",
                             (uint8_t*) write, write_len))
    {
        fprintf_light_red(stderr, "Failed setting data for dirdata:%"
                                  PRIu64"\n", dir);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int __emit_file_bytes(uint8_t* write, struct kv_store* store, 
                      char* vmname, uint64_t write_counter,
                      char* pointer, size_t write_len, uint64_t sector)
{
    struct bson_info* bson = bson_init();
    struct bson_kv val;
    uint64_t start, end, file;
    uint64_t fsize;
    size_t len = 4096;
    char path[len];
    char* token, *channel_name;

    fprintf_light_white(stdout, "__emit_file_bytes()\n");

    strtok(pointer, ":");
    token = strtok(NULL, ":");
    if (token)
    {
        sscanf(token, "%"SCNu64, &start);
    }
    else
    {
        fprintf_light_red(stderr, "Failed tokenizing start.\n");
        return EXIT_FAILURE;
    }

    strtok(NULL, ":");
    token = strtok(NULL, ":");
    if (token)
    {
        sscanf(token, "%"SCNu64, &end);
    }
    else
    {
        fprintf_light_red(stderr, "Failed tokenizing end.\n");
        return EXIT_FAILURE;
    }

    strtok(NULL, ":");
    token = strtok(NULL, ":");
    if (token)
    {
        sscanf(token, "%"SCNu64, &file);
    }
    else
    {
        fprintf_light_red(stderr, "Failed tokenizing end.\n");
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "start: %"PRIu64
                                " end: %"PRIu64
                                " file: %"PRIu64"\n", start, end, file);

    if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "path",
                             (uint8_t*) path, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving path for file:%"
                                  PRIu64"\n", file);
        return EXIT_FAILURE;
    }

    path[len] = '\0';
    fprintf_light_white(stdout, "path: %s\n", path);

    len = sizeof(fsize);
    if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "size",
                             (uint8_t*) &fsize, &len))
    {
        fprintf_light_red(stderr, "Failed retrieving size for file:%"
                                  PRIu64"\n", fsize);
        return EXIT_FAILURE;
    }

    channel_name = construct_channel_name(vmname, path);

    fprintf_light_white(stdout, "fsize: %"PRIu64"\n", fsize);
    fprintf_light_white(stdout, "channel_name: %s\n", channel_name);

    /* get path, emit on chan */

    val.type = BSON_STRING;
    val.size = strlen("data");
    val.key = "type";
    val.data = "data";

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "transaction";
    val.data = &(write_counter);

    bson_serialize(bson, &val);

    val.type = BSON_INT64;
    val.key = "start";
    val.data = &(start);

    bson_serialize(bson, &val);

    if (write_len >= fsize - start)
    {
        write_len = fsize - start;
        /* keep this "last block" always around */
        redis_enqueue_pipelined(store, sector, write, write_len);
    }

    if (end >= fsize)
    {
        end = fsize;
    }
    else
    {
        redis_delqueue_pipelined(store, sector); 
    }
    
    val.type = BSON_INT64;
    val.key = "end";
    val.data = &(end);

    bson_serialize(bson, &val);

    val.type = BSON_BINARY;
    val.key = "write";
    val.data = write;
    val.size = write_len;

    bson_serialize(bson, &val);

    bson_finalize(bson);

    fprintf_light_white(stdout, "publishing message\n");
        
    if (redis_publish(store, channel_name, bson->buffer,
                      (size_t) bson->position))
    {
        fprintf_light_red(stderr, "Failure publishing "
                                  "Redis message.\n");
        return -1;
    }

    fprintf_light_white(stdout, "freeing channel\n");
    free(channel_name);
    fprintf_light_white(stdout, "cleaning up bson\n");
    bson_cleanup(bson);

    return EXIT_SUCCESS;
}

int __diff_superblock(uint8_t* write, struct kv_store* store, 
                      char* vmname, uint64_t write_counter, 
                      char* pointer, size_t write_len)
{
    uint64_t fs = 0, superblock_offset = 0;
    size_t len = sizeof(struct ext4_superblock);
    struct ext4_superblock* new, oldd, *old = &oldd;
    char* channel = NULL;
    fprintf_light_white(stdout, "__diff_superblock()\n");

    fprintf_light_white(stdout, "working on: %s\n", pointer);

    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &fs);

    fprintf_light_white(stdout, "pulling superblock: %"PRIu64"\n", fs);

    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET, fs,
                             "superblock", (uint8_t*) old, &len))
    {
        fprintf_light_red(stderr, "Error getting superblock fs:%"
                                  PRIu64"\n", fs);
        return EXIT_FAILURE;
    }

    len = sizeof(superblock_offset);
    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET, fs,
                             "superblock_offset", 
                             (uint8_t*) &superblock_offset, &len))
    {
        fprintf_light_red(stderr, "Failed getting superblock_offset fs:%"
                                  PRIu64"\n", fs);
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "superblock_offset: %"PRIu64"\n",
                                superblock_offset);

    new = (struct ext4_superblock *) &(write[superblock_offset]);
    channel = construct_channel_name(vmname, "");

    FIELD_COMPARE(s_inodes_count, "s_inodes_count", "metadata", BSON_INT32)
    FIELD_COMPARE(s_blocks_count_lo, "s_blocks_count_lo", "metadata", BSON_INT32)
    FIELD_COMPARE(s_r_blocks_count_lo, "s_r_blocks_count_lo", "metadata", BSON_INT32)
    FIELD_COMPARE(s_free_blocks_count_lo, "s_free_blocks_count_lo", "metadata", BSON_INT32)
    FIELD_COMPARE(s_free_inodes_count, "s_free_inodes_count", "metadata", BSON_INT32)
    FIELD_COMPARE(s_first_data_block, "s_first_data_block", "metadata", BSON_INT32)
    FIELD_COMPARE(s_log_block_size, "s_log_block_size", "metadata", BSON_INT32)
    FIELD_COMPARE(s_log_cluster_size, "s_log_cluster_size", "metadata", BSON_INT32)
    FIELD_COMPARE(s_blocks_per_group, "s_blocks_per_group", "metadata", BSON_INT32)
    FIELD_COMPARE(s_clusters_per_group, "s_clusters_per_group", "metadata", BSON_INT32)
    FIELD_COMPARE(s_inodes_per_group, "s_inodes_per_group", "metadata", BSON_INT32)
    FIELD_COMPARE(s_mtime, "s_mtime", "metadata", BSON_INT32)
    FIELD_COMPARE(s_wtime, "s_wtime", "metadata", BSON_INT32)
    FIELD_COMPARE(s_mnt_count, "s_mnt_count", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_max_mnt_count, "s_max_mnt_count", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_magic, "s_magic", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_state, "s_state", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_errors, "s_errors", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_minor_rev_level, "s_minor_rev_level", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_lastcheck, "s_lastcheck", "metadata", BSON_INT32)
    FIELD_COMPARE(s_checkinterval, "s_checkinterval", "metadata", BSON_INT32)
    FIELD_COMPARE(s_creator_os, "s_creator_os", "metadata", BSON_INT32)
    FIELD_COMPARE(s_rev_level, "s_rev_level", "metadata", BSON_INT32)
    FIELD_COMPARE(s_def_resuid, "s_def_resuid", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_def_resgid, "s_def_resgid", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_first_ino, "s_first_ino", "metadata", BSON_INT32)
    FIELD_COMPARE(s_inode_size, "s_inode_size", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_block_group_nr, "s_block_group_nr", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_feature_compat, "s_feature_compat", "metadata", BSON_INT32)
    FIELD_COMPARE(s_feature_incompat, "s_feature_incompat", "metadata", BSON_INT32)
    FIELD_COMPARE(s_feature_ro_compat, "s_feature_ro_compat", "metadata", BSON_INT32)
    FIELD_COMPARE(s_uuid[15], "s_uuid[15]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_volume_name[15], "s_volume_name[15]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_last_mounted[63], "s_last_mounted[63]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_algorithm_usage_bitmap, "s_algorithm_usage_bitmap", "metadata", BSON_INT32)
    FIELD_COMPARE(s_prealloc_blocks, "s_prealloc_blocks", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_prealloc_dir_blocks, "s_prealloc_dir_blocks", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_reserved_gdt_blocks, "s_reserved_gdt_blocks", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_journal_uuid[15], "s_journal_uuid[15]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_journal_inum, "s_journal_inum", "metadata", BSON_INT32)
    FIELD_COMPARE(s_journal_dev, "s_journal_dev", "metadata", BSON_INT32)
    FIELD_COMPARE(s_last_orphan, "s_last_orphan", "metadata", BSON_INT32)
    FIELD_COMPARE(s_hash_seed[3], "s_hash_seed[3]", "metadata", BSON_INT32)
    FIELD_COMPARE(s_def_hash_version, "s_def_hash_version", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_jnl_backup_type, "s_jnl_backup_type", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_desc_size, "s_desc_size", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_default_mount_opts, "s_default_mount_opts", "metadata", BSON_INT32)
    FIELD_COMPARE(s_first_meta_bg, "s_first_meta_bg", "metadata", BSON_INT32)
    FIELD_COMPARE(s_mkfs_time, "s_mkfs_time", "metadata", BSON_INT32)
    FIELD_COMPARE(s_jnl_blocks[16], "s_jnl_blocks[16]", "metadata", BSON_INT32)
    FIELD_COMPARE(s_blocks_count_hi, "s_blocks_count_hi", "metadata", BSON_INT32)
    FIELD_COMPARE(s_r_blocks_count_hi, "s_r_blocks_count_hi", "metadata", BSON_INT32)
    FIELD_COMPARE(s_free_blocks_count_hi, "s_free_blocks_count_hi", "metadata", BSON_INT32)
    FIELD_COMPARE(s_min_extra_isize, "s_min_extra_isize", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_want_extra_isize, "s_want_extra_isize", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_flags, "s_flags", "metadata", BSON_INT32)
    FIELD_COMPARE(s_raid_stride, "s_raid_stride", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_mmp_update_interval, "s_mmp_update_interval", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_mmp_block, "s_mmp_block", "metadata", BSON_INT64)
    FIELD_COMPARE(s_raid_stripe_width, "s_raid_stripe_width", "metadata", BSON_INT32)
    FIELD_COMPARE(s_log_groups_per_flex, "s_log_groups_per_flex", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_checksum_type, "s_checksum_type", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_reserved_pad, "s_reserved_pad", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_kbytes_written, "s_kbytes_written", "metadata", BSON_INT64)
    FIELD_COMPARE(s_snapshot_inum, "s_snapshot_inum", "metadata", BSON_INT32)
    FIELD_COMPARE(s_snapshot_id, "s_snapshot_id", "metadata", BSON_INT32)
    FIELD_COMPARE(s_snapshot_r_blocks_count, "s_snapshot_r_blocks_count", "metadata", BSON_INT64)
    FIELD_COMPARE(s_snapshot_list, "s_snapshot_list", "metadata", BSON_INT32)
    FIELD_COMPARE(s_error_count, "s_error_count", "metadata", BSON_INT32)
    FIELD_COMPARE(s_first_error_time, "s_first_error_time", "metadata", BSON_INT32)
    FIELD_COMPARE(s_first_error_ino, "s_first_error_ino", "metadata", BSON_INT32)
    FIELD_COMPARE(s_first_error_block, "s_first_error_block", "metadata", BSON_INT64)
    FIELD_COMPARE(s_first_error_func[31], "s_first_error_func[31]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_first_error_line, "s_first_error_line", "metadata", BSON_INT32)
    FIELD_COMPARE(s_last_error_time, "s_last_error_time", "metadata", BSON_INT32)
    FIELD_COMPARE(s_last_error_ino, "s_last_error_ino", "metadata", BSON_INT32)
    FIELD_COMPARE(s_last_error_line, "s_last_error_line", "metadata", BSON_INT32)
    FIELD_COMPARE(s_last_error_block, "s_last_error_block", "metadata", BSON_INT64)
    FIELD_COMPARE(s_last_error_func[31], "s_last_error_func[31]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_mount_opts[63], "s_mount_opts[63]", "metadata", BSON_BINARY)
    FIELD_COMPARE(s_usr_quota_inum, "s_usr_quota_inum", "metadata", BSON_INT32)
    FIELD_COMPARE(s_grp_quota_inum, "s_grp_quota_inum", "metadata", BSON_INT32)
    FIELD_COMPARE(s_overhead_clusters, "s_overhead_clusters", "metadata", BSON_INT32)
    FIELD_COMPARE(s_reserved[107], "s_reserved[107]", "metadata", BSON_INT32)
    FIELD_COMPARE(s_checksum, "s_checksum", "metadata", BSON_INT32)
    
    free(channel);

    len = sizeof(*new);
    if (redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, fs,
                             "superblock", (uint8_t*) new, len))
    {
        fprintf_light_red(stderr, "Error writing new superblock back: %"
                                  PRIu64"\n", fs);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int __diff_mbr(uint8_t* write, struct kv_store* store,
               const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_mbr()\n");
    return EXIT_SUCCESS;
}

int __diff_bgds(uint8_t* write, struct kv_store* store,
                char* vmname, uint64_t write_counter, char* pointer,
                size_t write_len)
{
    uint64_t bgd = 0, lbgds = 0, i;
    uint8_t** list;
    size_t len = 0, bgdlen = sizeof(struct ext4_block_group_descriptor);
    struct ext4_block_group_descriptor oldd, *old = &oldd, *new;
    char* channel, *path = "";
    fprintf_light_white(stdout, "__diff_bgds()\n");
    fprintf_light_white(stdout, "pointer: %s\n", pointer);

    // pull list
    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &lbgds);

    if (redis_list_get(store, REDIS_BGDS_LGET, lbgds, &list, &len))
    {
        fprintf_light_red(stdout, "Error getting list of bgds from Redis.\n");
        return EXIT_FAILURE;
    }

    fprintf_light_cyan(stdout, "loaded: %zu elements\n", len);
    channel = construct_channel_name(vmname, path);
    fprintf_light_cyan(stdout, "channel: %s\n", channel);

    for (i = 0; i < len; i++)
    {
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &bgd);

        if (redis_hash_field_get(store, REDIS_BGD_SECTOR_GET, bgd,
                                 "bgd", (uint8_t*) old, &bgdlen))
        {
            fprintf_light_red(stderr, "Could not load BGD %"PRIu64"\n", bgd);
            return EXIT_FAILURE;
        }

        new = (struct ext4_block_group_descriptor *)
            &(write[i*sizeof(struct ext4_block_group_descriptor)]);

        FIELD_COMPARE(bg_block_bitmap_lo, "bgd.bg_block_bitmap_lo", "metadata", BSON_INT32);
        FIELD_COMPARE(bg_inode_bitmap_lo, "bgd.bg_inode_bitmap_lo", "metadata", BSON_INT32);
        FIELD_COMPARE(bg_inode_table_lo, "bgd.bg_inode_table_lo,", "metadata", BSON_INT32);
        FIELD_COMPARE(bg_free_blocks_count_lo, "bgd.bg_free_blocks_count_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_free_inodes_count_lo, "bgd.bg_free_inodes_count_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_used_dirs_count_lo, "bgd.bg_used_dirs_count_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_flags, "bgd.bg_flags", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_exclude_bitmap_lo, "bgd.bg_exclude_bitmap_lo", "metadata", BSON_INT32);
        FIELD_COMPARE(bg_block_bitmap_csum_lo, "bgd.bg_block_bitmap_csum_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_inode_bitmap_csum_lo, "bgd.bg_inode_bitmap_csum_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_itable_unused_lo, "bgd.bg_itable_unused_lo", "metadata", BSON_BINARY);
        FIELD_COMPARE(bg_checksum, "bgd.bg_checksum", "metadata", BSON_BINARY);

        if (redis_hash_field_set(store, REDIS_BGD_SECTOR_INSERT, bgd, "bgd",
                                 (uint8_t*) new, sizeof(*new)))
        {
            fprintf_light_red(stderr, "Error setting bgd %"PRIu64"\n", bgd);
            return EXIT_FAILURE;
        }
    } 

    redis_free_list(list, len);
    free(channel);
    return EXIT_SUCCESS;
}

int __ext4_new_extent_leaf_block(struct kv_store* store, uint64_t file,
                                 uint64_t block, struct ext4_superblock* super,
                                 uint64_t partition_offset, uint64_t write_counter,
                                 char* vmname) 
{
    uint64_t sector = block * ext4_block_size(*super);
    sector += partition_offset;
    sector /= SECTOR_SIZE;
    
    redis_hash_field_set(store, REDIS_EXTENT_SECTOR_INSERT,
                         sector, "file", (uint8_t*) &file, sizeof(file));

    if (redis_reverse_pointer_set(store, REDIS_EXTENTS_INSERT,
                          file,
                          sector))
    {
        return EXIT_FAILURE;
    }

    if (redis_reverse_pointer_set(store, REDIS_EXTENTS_SECTOR_INSERT,
                          sector,
                          file))
    {
        return EXIT_FAILURE;
    }

    __reinspect_write(super, store, partition_offset, sector, write_counter,
                      vmname);

    return EXIT_SUCCESS;
}

int __ext4_new_extent(struct kv_store* store, uint64_t file,
                      struct ext4_superblock* super,
                      uint64_t partition_offset, struct ext4_extent* extent_new,
                      char* vmname, uint64_t write_counter)
{
    uint64_t block_size = ext4_block_size(*super);
    uint64_t sector = ext4_extent_start(*extent_new) * block_size;
    sector += partition_offset;
    sector /= SECTOR_SIZE;
    uint64_t sectors_per_block = block_size / SECTOR_SIZE;
    uint64_t i, counter = extent_new->ee_block * block_size;


    for (i = 0; i < extent_new->ee_len; i++)
    {
        redis_reverse_pointer_set(store, REDIS_FILE_SECTORS_INSERT,
                                  file, 
                                  sector);
        redis_reverse_file_data_pointer_set(store, 
                                            sector,
                                            counter, counter + block_size,
                                            file);
        D_PRINT64(counter);
        D_PRINT64(extent_new->ee_block);
        D_PRINT64(file);

        __reinspect_write(super, store, partition_offset,
                          sector, write_counter,
                          vmname);

        counter += block_size;        
        sector += sectors_per_block;
        
    }

    return EXIT_SUCCESS;
}

int __diff_ext4_extents(struct kv_store* store, char* vmname, uint64_t file,
                        uint64_t write_counter, uint8_t* newb, uint8_t* oldb,
                        uint64_t partition_offset,
                        struct ext4_superblock* super)
{
    struct ext4_extent_header* hdr_new, *hdr_old;
    struct ext4_extent_idx* idx_new, *idx_old;
    struct ext4_extent* extent_new, *extent_old;

    struct ext4_extent_header hdr_def = { .eh_magic = 0,
                                          .eh_entries = 0,
                                          .eh_max = 0,
                                          .eh_depth = 0,
                                          .eh_generation = 0
                                        };
    
    struct ext4_extent_idx idx_def = { .ei_block = 0,
                                       .ei_leaf_lo = 0,
                                       .ei_leaf_hi = 0,
                                       .ei_unused = 0
                                     };

    struct ext4_extent extent_def = { .ee_block = 0,
                                      .ee_len = 0,
                                      .ee_start_hi = 0,
                                      .ee_start_lo = 0
                                    };

    uint64_t new_entries = 0, old_entries = 0, old_counter = 0, new_counter = 0;
    
    hdr_new = (struct ext4_extent_header*) newb;
    hdr_old = (struct ext4_extent_header*) oldb;

    if (hdr_new->eh_magic != 0xF30A)
        hdr_new = &hdr_def;
    if (hdr_old->eh_magic != 0xF30A)
        hdr_old = &hdr_def;

    new_entries = hdr_new->eh_entries;
    old_entries  = hdr_old->eh_entries;

    fprintf_light_cyan(stdout, "__ext4_diff_extents()\n");
    D_PRINT16(hdr_new->eh_magic);
    D_PRINT16(hdr_old->eh_magic);

    while (new_entries)
    {
        D_PRINT16(new_entries);
        D_PRINT16(old_entries);

        D_PRINT16(hdr_new->eh_depth);
        D_PRINT16(hdr_old->eh_depth);

        if (old_entries == 0)
        {
            idx_old = &idx_def;
            hdr_old = &hdr_def;
            extent_old = &extent_def;
        }

        if (hdr_new->eh_depth)
        {
            idx_new = (struct ext4_extent_idx *)
                      &(newb[sizeof(struct ext4_extent_header) +
                             sizeof(struct ext4_extent_idx) * new_counter]);

            if (hdr_old->eh_depth)
            {
                idx_old = (struct ext4_extent_idx *)
                          &(oldb[sizeof(struct ext4_extent_header) +
                                 sizeof(struct ext4_extent_idx)*old_counter]);

                if (ext4_extent_index_leaf(*idx_new) !=
                    ext4_extent_index_leaf(*idx_old))
                {
                    D_PRINT64(ext4_extent_index_leaf(*idx_new));
                    D_PRINT64(ext4_extent_index_leaf(*idx_old));
                    fprintf_light_white(stdout, "found new extent position.\n");

                    __ext4_new_extent_leaf_block(store, file,
                                              ext4_extent_index_leaf(*idx_new),
                                              super, partition_offset,
                                              write_counter, vmname);
                }
                    D_PRINT64(ext4_extent_index_leaf(*idx_new));
                    D_PRINT64(ext4_extent_index_leaf(*idx_old));
            }
            else
            {
                __ext4_new_extent_leaf_block(store, file,
                                          ext4_extent_index_leaf(*idx_new),
                                          super, partition_offset,
                                          write_counter, vmname);
            }
        }
        else
        {
            extent_new = (struct ext4_extent *)
                      &(newb[sizeof(struct ext4_extent_header) +
                             sizeof(struct ext4_extent) * new_counter]);
            fprintf_light_white(stdout, "no depth new\n");
            if (hdr_old->eh_depth == 0)
            {
                fprintf_light_white(stdout, "no depth old\n");
                if (old_entries)
                {
                    extent_old = (struct ext4_extent *)
                          &(oldb[sizeof(struct ext4_extent_header) +
                                 sizeof(struct ext4_extent) * old_counter]);
                }

                D_PRINT64(ext4_extent_start(*extent_new));
                D_PRINT64(ext4_extent_start(*extent_old));

                D_PRINT16(extent_new->ee_len);
                D_PRINT16(extent_old->ee_len);

                if ((ext4_extent_start(*extent_new) !=
                     ext4_extent_start(*extent_old)) ||
                    (extent_new->ee_len != extent_old->ee_len))
                {
                    fprintf_light_white(stdout, "adding new extents as start "
                                                "shifted.\n");
                    __ext4_new_extent(store, file, super, partition_offset,
                                      extent_new, vmname, write_counter);
                }
                else
                {
                    fprintf_light_cyan(stdout, "Extents exactly match.\n");
                }
            }
            else
            {
                __ext4_new_extent(store, file, super, partition_offset,
                                  extent_new, vmname, write_counter);
                /* deleted index */
            }
        }

        if (old_entries)
        {
            old_entries--;
            old_counter++;
        }

        if (new_entries)
        {
            new_entries--;
            new_counter++;
        }
    }

    while (old_entries--)
    {
        fprintf_light_red(stderr, "LARGE deletion quickly of extent tree "
                                  "associated with a file.");
        /* ALL deletions */
    }
    
    return EXIT_SUCCESS; 
}

int __diff_inodes(uint8_t* write, struct kv_store* store,
                  char* vmname, uint64_t write_counter, char* pointer,
                  size_t write_len, struct ext4_superblock* super,
                  uint64_t partition_offset)
{
    uint64_t file = 0, lfiles = 0, i, offset, new_size, old_size, last_sector;
    uint8_t** list;
    size_t len = 0, len2 = 4096;
    struct ext4_inode oldd, *old = &oldd, *new;
    char* channel = NULL, path[len2];
    
    fprintf_light_white(stdout, "__diff_inodes()\n");
    fprintf_light_white(stdout, "pointer: %s\n", pointer);

    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &lfiles);

    if (redis_list_get(store, REDIS_FILES_LGET, lfiles, &list, &len))
    {
        fprintf_light_red(stdout, "Error getting list of bgds from Redis.\n");
        return EXIT_FAILURE;
    }

    for (i = 0; i < len; i++)
    {
        len2 = 4096;
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &file);

        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "path",
                                 (uint8_t*) path, &len2))
        {
            fprintf_light_red(stdout, "Error getting path for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        path[len2] = '\0';

        len2 = sizeof(offset);
        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "inode_offset",
                                 (uint8_t*) &offset, &len2))
        {
            fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        len2 = sizeof(struct ext4_inode);
        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "inode",
                                 (uint8_t*) old, &len2))
        {
            fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        if (len2 == 0)
        {
            memset(&oldd, 0, sizeof(oldd));
        }

        new = (struct ext4_inode*) &(write[offset]);
        old_size = ext4_file_size(*old);

        fprintf_light_white(stdout, "Checking inode for file '%s', offset %"
                                    PRIu64"\n", path, offset);
        channel = construct_channel_name(vmname, path);
        fprintf_light_cyan(stdout, "channel: %s\n", channel);

        FIELD_COMPARE(i_mode, "i_mode", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_uid, "i_uid", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_size_lo, "i_size_lo", "metadata", BSON_INT32)
        FIELD_COMPARE(i_atime, "i_atime", "metadata", BSON_INT32)
        FIELD_COMPARE(i_ctime, "i_ctime", "metadata", BSON_INT32)
        FIELD_COMPARE(i_mtime, "i_mtime", "metadata", BSON_INT32)
        FIELD_COMPARE(i_dtime, "i_dtime", "metadata", BSON_INT32)
        FIELD_COMPARE(i_gid, "i_gid", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_links_count, "i_links_count", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_blocks_lo, "i_blocks_lo", "metadata", BSON_INT32)
        FIELD_COMPARE(i_flags, "i_flags", "metadata", BSON_INT32)
        FIELD_COMPARE(i_osd1[0], "i_osd1[0]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd1[1], "i_osd1[1]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd1[2], "i_osd1[2]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd1[3], "i_osd1[3]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_block[0], "i_block[0]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[1], "i_block[1]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[2], "i_block[2]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[3], "i_block[3]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[4], "i_block[4]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[5], "i_block[5]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[6], "i_block[6]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[7], "i_block[7]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[8], "i_block[8]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[9], "i_block[9]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[10], "i_block[10]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[11], "i_block[11]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[12], "i_block[12]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[13], "i_block[13]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_block[14], "i_block[14]", "metadata", BSON_INT32)
        FIELD_COMPARE(i_generation, "i_generation", "metadata", BSON_INT32)
        FIELD_COMPARE(i_file_acl_lo, "i_file_acl_lo", "metadata", BSON_INT32)
        FIELD_COMPARE(i_size_high, "i_size_high", "metadata", BSON_INT32)
        FIELD_COMPARE(i_obso_faddr, "i_obso_faddr", "metadata", BSON_INT32)
        FIELD_COMPARE(i_osd2[0], "i_osd2[0]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[1], "i_osd2[1]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[2], "i_osd2[2]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[3], "i_osd2[3]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[4], "i_osd2[4]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[5], "i_osd2[5]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[6], "i_osd2[6]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[7], "i_osd2[7]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[8], "i_osd2[8]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[9], "i_osd2[9]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_osd2[10], "i_osd2[10]", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_extra_isize, "i_extra_isize", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_checksum_hi, "i_checksum_hi", "metadata", BSON_BINARY)
        FIELD_COMPARE(i_ctime_extra, "i_ctime_extra", "metadata", BSON_INT32)
        FIELD_COMPARE(i_mtime_extra, "i_mtime_extra", "metadata", BSON_INT32)
        FIELD_COMPARE(i_atime_extra, "i_atime_extra", "metadata", BSON_INT32)
        FIELD_COMPARE(i_crtime, "i_crtime", "metadata", BSON_INT32)
        FIELD_COMPARE(i_crtime_extra, "i_crtime_extra", "metadata", BSON_INT32)
        FIELD_COMPARE(i_version_hi, "i_version_hi", "metadata", BSON_INT32)

        /* diff ext4_extent_header() */
        /* if eh_entries diff */
        /*      if depth same, just update any extra intermediates */
        /*      depth == 0 --> sector mappings */
        /*      depth > 0 --> intermediate mappings */
        /* if eh_max diff */
        /* if depth diff --> add intermediate extent (check keyspace schema) */
        /*      number added/diffed depends on eh_entries */
        /* generation don't care */
        if (((new->i_mode & 0x8000) == 0x8000 ||
             (new->i_mode & 0x4000) == 0x4000) &&
            !((new->i_mode & 0x6000) == 0x6000 ||
              (new->i_mode & 0xa000) == 0xa000))
        {
            __diff_ext4_extents(store, vmname, file, write_counter, 
                                (uint8_t *) &(new->i_block[0]),
                                (uint8_t *) &(old->i_block[0]), partition_offset, super);
        }

        len2 = sizeof(struct ext4_inode);
        if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, file, "inode",
                                 (uint8_t*) new, len2))
        {
            fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        new_size = ext4_file_size(*new);
        len2 = sizeof(new_size);

        if (old_size < new_size)
        {
            if (redis_last_file_sector(store, file, &last_sector))
            {
                fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                          "from Redis.\n", file);
                return EXIT_FAILURE;
            }
            fprintf_light_white(stdout, "Size mismatch. Checking for last "
                                        "block\n %"PRIu64" %"PRIu64, old_size, new_size);

            __reinspect_write(super, store, partition_offset, last_sector,
                              write_counter, vmname);
        }

        if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, file, "size",
                                 (uint8_t*) &new_size, len2))
        {
            fprintf_light_red(stdout, "Error inserting new size.\n", file);
            return EXIT_FAILURE;
        }
        free(channel);
    }

    fprintf_light_cyan(stdout, "loaded: %zu elements\n", len);
    return EXIT_SUCCESS;
}

int __diff_bitmap(uint8_t* write, struct kv_store* store,
                  const char* vmname, const char* pointer)
{
    fprintf_light_white(stdout, "__diff_bitmap()\n");
    return EXIT_SUCCESS;
}

int __diff_extent_tree(uint8_t* write, struct kv_store* store,
                       char* vmname, char* pointer,
                       uint64_t write_counter, size_t write_len,
                       struct ext4_superblock* super,
                       uint64_t partition_offset)
{
    size_t len = ext4_block_size(*super), len2 = sizeof(uint64_t);
    uint8_t buf[len];
    uint64_t id, file;
    struct ext4_extent_header def = { .eh_magic = 0,
                                      .eh_entries = 0,
                                      .eh_max = 0,
                                      .eh_depth = 0,
                                      .eh_generation = 0
                                    };

    memset(&def, 0, sizeof(def));
    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &id);

    fprintf_light_white(stdout, "__diff_extent_tree()\n");
    D_PRINT64(id);
    /* load old extent block file id */
    if (redis_hash_field_get(store, REDIS_EXTENT_SECTOR_GET, id, "file",
                             (uint8_t*) &file, &len2))
    {
        fprintf_light_red(stderr, "No old index?\n");
    }

    /* load old extent block */
    if (redis_hash_field_get(store, REDIS_EXTENT_SECTOR_GET, id, "data", buf,
                             &len))
    {
        fprintf_light_red(stderr, "No old index?\n");
        len = sizeof(def);
        memcpy(buf, &def, sizeof(def));
    }

    __diff_ext4_extents(store, vmname, file, write_counter, write, buf,
                        partition_offset, super);

    /* set new extent block */
    if (redis_hash_field_set(store, REDIS_EXTENT_SECTOR_INSERT, id, "data", write,
                             write_len))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int __qemu_dispatch_write(uint8_t* data,
                          struct kv_store* store, char* vmname,
                          uint64_t write_counter,
                          char* pointer, size_t len,
                          struct ext4_superblock* super,
                          uint64_t partition_offset,
                          uint64_t sector)
{
    D_PRINT64(partition_offset);
    fprintf_light_blue(stdout, "pointer: %s\n", pointer);
    if (strncmp(pointer, "start", strlen("start")) == 0)
        __emit_file_bytes(data, store, vmname, write_counter, pointer, len,
                          sector);
    else if(strncmp(pointer, "fs", strlen("fs")) == 0)
        __diff_superblock(data, store, vmname, write_counter, pointer, len);
    else if(strncmp(pointer, "mbr", strlen("mbr")) == 0)
        __diff_mbr(data, store, vmname, pointer);
    else if(strncmp(pointer, "lbgds", strlen("lbgds")) == 0)
        __diff_bgds(data, store, vmname, write_counter, pointer, len);
    else if(strncmp(pointer, "lfiles", strlen("lfiles")) == 0)
        __diff_inodes(data, store, vmname, write_counter, pointer, len, super,
                      partition_offset);
    else if(strncmp(pointer, "bgd", strlen("bgd")) == 0)
        __diff_bitmap(data, store, vmname, pointer);
    else if(strncmp(pointer, "extent", strlen("extent")) == 0)
        __diff_extent_tree(data, store, vmname, pointer, write_counter, len, 
                           super, partition_offset);
    else if(strncmp(pointer, "dirdata", strlen("dirdata")) == 0)
        __diff_dir2(data, store, vmname, write_counter, pointer, len,
                    super, partition_offset);
    else
    {
        fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                      pointer);
    }
    return EXIT_SUCCESS;
}

int qemu_deep_inspect(struct ext4_superblock* superblock,
                      struct qemu_bdrv_write* write,
                      struct kv_store* store, uint64_t write_counter,
                      char* vmname, uint64_t partition_offset)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t block_size = ext4_block_size(*superblock);
    uint64_t size = 0;
    uint8_t* data;

    for (i = 0; i < write->header.nb_sectors; i += block_size / SECTOR_SIZE)
    {
        len = 1024;
        if (redis_sector_lookup(store, write->header.sector_num + i,
            result, &len))
        {
            fprintf_light_red(stderr, "Error doing sector lookup.\n");
            if ((write->header.nb_sectors - i) * SECTOR_SIZE < block_size)
            {
                size = (write->header.nb_sectors - i) * SECTOR_SIZE;
            }
            else
            {
                size = block_size;
            }

            redis_enqueue_pipelined(store, write->header.sector_num + i,
                                    &(write->data[i*SECTOR_SIZE]),
                                    size);
            continue;
        } 

        if (len)
        {
            result[len] = 0;
            data = &(write->data[i*SECTOR_SIZE]);

            if ((write->header.nb_sectors - i) * SECTOR_SIZE < block_size)
            {
                size = (write->header.nb_sectors - i)* SECTOR_SIZE;
            }
            else
            {
                size = block_size;
            }

            D_PRINT64(partition_offset);
            __qemu_dispatch_write(data, store, vmname, write_counter,
                                  (char *) result, (size_t) size, superblock,
                                  partition_offset, write->header.sector_num);
        }
        else
        {
            fprintf_light_red(stderr, "Returned sector lookup empty.\n");
            if ((write->header.nb_sectors - i) * SECTOR_SIZE < block_size)
            {
                size = (write->header.nb_sectors - i) * SECTOR_SIZE;
            }
            else
            {
                size = block_size;
            }

            redis_enqueue_pipelined(store, write->header.sector_num + i,
                                    &(write->data[i*SECTOR_SIZE]),
                                    size);
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

int qemu_get_pt_offset(struct kv_store* store,
                       uint64_t* partition_offset,
                       uint64_t pt_id)
{
    uint32_t sector_offset = 0;
    size_t len = sizeof(sector_offset);

    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET,
                             pt_id, "first_sector_lba",
                             (uint8_t*) &sector_offset, &len))
    {
        fprintf_light_red(stderr, "Error retrieving first_sector_lba\n");
        return EXIT_FAILURE;
    }

    *partition_offset = sector_offset * SECTOR_SIZE; 

    return EXIT_SUCCESS;
}

enum SECTOR_TYPE __sector_type(const char* str)
{
    if (strncmp(str, "start", strlen("start")) == 0 ||
        strncmp(str, "dirdata", strlen("dirdata")) == 0)
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
                     uint64_t id, struct ext4_superblock* super)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "superblock") == 0)
        { 
            memcpy(super, value1.data, sizeof(struct ext4_superblock));
        }

        if (strcmp(value1.key, "superblock_sector") == 0)
        { 
            if (redis_reverse_pointer_set(store, REDIS_SUPERBLOCK_INSERT,
                                          *((uint64_t*) value1.data), id))
                return EXIT_FAILURE;
        }             

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

int __deserialize_file(struct ext4_superblock* superblock,
                       struct bson_info* bson, struct kv_store* store,
                       uint64_t id)
{
    struct bson_info* bson2;
    struct bson_kv value1, value2;
    uint64_t block_size = ext4_block_size(*superblock);

    uint64_t counter = 0, sector = 0;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "inode_sector") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_FILES_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;

            if (redis_reverse_pointer_set(store, REDIS_FILES_SECTOR_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      (uint64_t) *((uint32_t *) value1.data)))
                return EXIT_FAILURE;
        }
        else if (strcmp(value1.key, "inode_num") == 0)
        {
            if (redis_reverse_pointer_set(store, REDIS_INODE_INSERT,
                                      (uint64_t) *((uint32_t *) value1.data),
                                      id))
                return EXIT_FAILURE;

            if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
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

                if (redis_hash_field_set(store, REDIS_DIR_SECTOR_INSERT,
                                         sector, "file", (uint8_t*) &id, sizeof(id)))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }

                if (redis_hash_field_set(store, REDIS_DIR_SECTOR_INSERT, sector,
                                 "data", (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }


                if (redis_reverse_pointer_set(store, REDIS_DIR_INSERT,
                                      sector,
                                      sector))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }
            }

            bson_cleanup(bson2);
        }
        else if (strcmp(value1.key, "sectors") == 0)
        {
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
                redis_reverse_pointer_set(store, REDIS_FILE_SECTORS_INSERT,
                                       id, 
                                       (uint64_t) *((uint32_t *) value1.data));
                redis_reverse_file_data_pointer_set(store, 
                        (uint64_t) *((uint32_t*)value1.data),
                        counter, counter + block_size, id);
                counter += block_size; 
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
                sscanf((const char*) value1.key, "%"SCNu64, &sector);

                if (redis_hash_field_set(store, REDIS_EXTENT_SECTOR_INSERT,
                                         sector, "file", (uint8_t*) &id, sizeof(id)))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }

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
                                      sector))
                {
                    bson_cleanup(bson2);
                    return EXIT_FAILURE;
                }
            }

            bson_cleanup(bson2);
        }
        else if (strcmp(value1.key, "path") == 0)
        {
            if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, id,
                                 value1.key, (const uint8_t*) value1.data,
                                 (size_t) value1.size))
                return EXIT_FAILURE;

            if (redis_path_set(store, (const uint8_t*) value1.data,
                               (size_t) value1.size, id))
               return EXIT_FAILURE; 
        }
        else
        {
            if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, id,
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
    struct ext4_superblock super;

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
            __deserialize_file(&super, bson, store, file_counter++);
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
            __deserialize_fs(bson, store, fs_id, &super);
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
