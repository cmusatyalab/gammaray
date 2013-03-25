#define _GNU_SOURCE
#include "__bson.h"
#include "bson.h"
#include "color.h"
#include "deep_inspection.h"
#include "ext4.h"
#include "ntfs.h"
#include "redis_queue.h"
#include "util.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <errno.h>
#include <unistd.h>

#ifndef HOST_NAME_MAX
    #define HOST_NAME_MAX 256
#endif

#define FILE_DATA_WRITE "data"
#define FILE_META_WRITE "metadata"
#define VM_NAME_MAX 512
#define PATH_MAX 4096

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)

#define D_PRINT64(val) { fprintf_light_yellow(stdout, "" \
                         STRINGIFY(val)" : %"PRIu64"\n", val); }
#define D_PRINT16(val) { fprintf_light_yellow(stdout, "" \
                         STRINGIFY(val)" : %"PRIu32"\n", (uint32_t) val); }

/*** Pre-Definitions ***/
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

int __reinspect_write(struct super_info* superblock, struct kv_store* store,
                      int64_t partition_offset, uint64_t sector,
                      uint64_t write_counter, char* vmname)
{
    uint8_t buf[superblock->block_size];
    size_t len = superblock->block_size;
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

    return qemu_deep_inspect(superblock, &write, store, write_counter, vmname,
                             partition_offset);
}

uint64_t __inode_sector(struct kv_store* store, struct super_info* super,
                        uint64_t inode)
{
    uint64_t block_group = (inode - 1) / super->inodes_per_group;
    uint64_t inode_table_sector;
    uint64_t inode_sector;
    uint64_t inode_offset = (inode - 1) % super->inodes_per_group;
    D_PRINT64(inode_offset);
    inode_offset *= super->inode_size;
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

    D_PRINT64(super->inodes_per_group);
    D_PRINT64(inode);
    D_PRINT64(block_group);
    D_PRINT64(inode_offset);
    D_PRINT64(inode_table_sector);
    
    inode_sector = (inode_table_sector * SECTOR_SIZE +
                    inode_offset) / SECTOR_SIZE;

    fprintf_light_white(stdout, "inode_sector: %"PRIu64"\n", inode_sector);
  
    return inode_sector;
}

uint64_t __inode_offset(struct kv_store* store, struct super_info* super,
                        uint64_t inode)
{
    uint64_t block_group = (inode - 1) / super->inodes_per_group;
    uint64_t inode_table_sector;
    uint64_t inode_offset = (inode - 1) % super->inodes_per_group;
    D_PRINT64(inode_offset);
    inode_offset *= super->inode_size;
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

    D_PRINT64(super->inodes_per_group);
    D_PRINT64(inode);
    D_PRINT64(block_group);
    D_PRINT64(inode_offset);
    D_PRINT64(inode_table_sector);

    return inode_offset;
}

int __diff_dir2(uint8_t* write, struct kv_store* store, 
               char* vmname, uint64_t write_counter,
               char* pointer, size_t write_len, struct super_info* superblock,
               uint64_t partition_offset)
{
    uint64_t dir;
    fprintf_light_white(stdout, "__diff_dir(), write_len == %zu\n", write_len);
    fprintf_light_white(stdout, "operating on: %s\n", pointer);

    strtok(pointer, ":");
    pointer = strtok(NULL, ":");

    if (pointer == NULL)
    {
        fprintf_light_red(stderr, "Failed parsing dir pointer.\n");
        return EXIT_FAILURE;
    }

    sscanf(pointer, "%"SCNu64, &dir);

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

int __diff_superblock_ntfs(uint8_t* write, struct kv_store* store, 
                      char* vmname, uint64_t write_counter, 
                      char* pointer, size_t write_len)
{
    uint64_t fs = 0, superblock_offset = 0;
    size_t len = sizeof(struct ntfs_boot_file);
    struct ntfs_boot_file* new, oldd, *old = &oldd;
    fprintf_light_white(stdout, "__diff_superblock_ntfs()\n");

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

    new = (struct ntfs_boot_file *) &(write[superblock_offset]);

    len = sizeof(struct ntfs_boot_file);
    /* TODO */
    //if (redis_hash_field_set(store, REDIS_SUPERBLOCK_SECTOR_INSERT, fs,
    //                         "superblock", (uint8_t*) new, len))
    //{
    //    fprintf_light_red(stderr, "Error writing new superblock back: %"
    //                              PRIu64"\n", fs);
    //    return EXIT_FAILURE;
    //}

    return EXIT_SUCCESS;
}

int __diff_superblock(uint8_t* write, struct kv_store* store, 
                      char* vmname, uint64_t write_counter, 
                      char* pointer, size_t write_len)
{
    uint64_t fs = 0, superblock_offset = 0;
    struct ext4_superblock* new;
    uint64_t new_block_size, block_size;
    size_t len;
    int32_t new_num_files, num_files;
    int32_t new_num_block_groups, num_block_groups;
    char* channel = NULL;

    fprintf_light_white(stdout, "__diff_superblock()\n");
    fprintf_light_white(stdout, "working on: %s\n", pointer);

    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &fs);

    fprintf_light_white(stdout, "pulling block_size: %"PRIu64"\n", fs);

    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs, block_size, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs, num_files, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs, num_block_groups, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs, superblock_offset, len);

    fprintf_light_white(stdout, "superblock_offset: %"PRIu64"\n",
                                superblock_offset);

    new = (struct ext4_superblock *) &(write[superblock_offset]);
    channel = construct_channel_name(vmname, "");

    new_block_size = ext4_block_size(*new);
    new_num_block_groups = (ext4_s_blocks_count(*new) +
                           (new->s_blocks_per_group - 1)) /
                           new->s_blocks_per_group;
    new_num_files = new->s_inodes_count -
                    new->s_free_inodes_count -
                    new->s_first_ino + 2;

    DIRECT_FIELD_COMPARE(block_size, "superblock.block_size", "metadata", BSON_INT64);
    DIRECT_FIELD_COMPARE(num_block_groups, "superblock.num_block_groups", "metadata", BSON_INT32);
    DIRECT_FIELD_COMPARE(num_files, "superblock.num_files", "metadata", BSON_INT32);

    free(channel);

    SET_FIELD(REDIS_SUPERBLOCK_SECTOR_INSERT, fs, block_size, len);
    SET_FIELD(REDIS_SUPERBLOCK_SECTOR_INSERT, fs, num_block_groups, len);
    SET_FIELD(REDIS_SUPERBLOCK_SECTOR_INSERT, fs, num_files, len);

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
                size_t write_len, struct super_info* superblock,
                uint64_t offset)
{
    uint64_t bgd = 0, lbgds = 0, i;
    uint8_t** list;
    size_t len;
    struct ext4_block_group_descriptor* new;
    char* channel, *path = "";
    uint64_t block_bitmap_sector_start, new_block_bitmap_sector_start;
    uint64_t inode_bitmap_sector_start, new_inode_bitmap_sector_start;
    uint64_t inode_table_sector_start, new_inode_table_sector_start;

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

        GET_FIELD(REDIS_BGD_SECTOR_GET, bgd, block_bitmap_sector_start, len);
        GET_FIELD(REDIS_BGD_SECTOR_GET, bgd, inode_bitmap_sector_start, len);
        GET_FIELD(REDIS_BGD_SECTOR_GET, bgd, inode_table_sector_start, len);

        new = (struct ext4_block_group_descriptor *)
            &(write[i*sizeof(struct ext4_block_group_descriptor)]);

        new_block_bitmap_sector_start = (ext4_bgd_block_bitmap(*new) *
                                        superblock->block_size +
                                        offset) /
                                        SECTOR_SIZE;
        new_inode_bitmap_sector_start = (ext4_bgd_inode_bitmap(*new) *
                                        superblock->block_size +
                                        offset) /
                                        SECTOR_SIZE;
        new_inode_table_sector_start = (ext4_bgd_inode_table(*new) *
                                        superblock->block_size +
                                        offset) /
                                        SECTOR_SIZE;

        DIRECT_FIELD_COMPARE(block_bitmap_sector_start, "bgd.block_bitmap_sector_start", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(inode_bitmap_sector_start, "bgd.inode_bitmap_sector_start", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(inode_table_sector_start, "bgd.inode_table_sector_start", "metadata", BSON_INT64);

        SET_FIELD(REDIS_BGD_SECTOR_INSERT, bgd, block_bitmap_sector_start, len);
        SET_FIELD(REDIS_BGD_SECTOR_INSERT, bgd, inode_bitmap_sector_start, len);
        SET_FIELD(REDIS_BGD_SECTOR_INSERT, bgd, inode_table_sector_start, len);
    } 

    redis_free_list(list, len);
    free(channel);
    return EXIT_SUCCESS;
}

int __ext4_new_extent_leaf_block(struct kv_store* store, uint64_t file,
                                 uint64_t block, struct super_info* superblock,
                                 uint64_t partition_offset, uint64_t write_counter,
                                 char* vmname) 
{
    uint64_t sector = block * superblock->block_size;
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

    __reinspect_write(superblock, store, partition_offset, sector, write_counter,
                      vmname);

    return EXIT_SUCCESS;
}

int __ext4_new_extent(struct kv_store* store, uint64_t file,
                      struct super_info* superblock, 
                      uint64_t partition_offset, struct ext4_extent* extent_new,
                      char* vmname, uint64_t write_counter)
{
    uint64_t sector = ext4_extent_start(*extent_new) * superblock->block_size;
    sector += partition_offset;
    sector /= SECTOR_SIZE;
    uint64_t sectors_per_block = superblock->block_size / SECTOR_SIZE;
    uint64_t i, counter = extent_new->ee_block * superblock->block_size;

    for (i = 0; i < extent_new->ee_len; i++)
    {
        redis_reverse_pointer_set(store, REDIS_FILE_SECTORS_INSERT,
                                  file, 
                                  sector);
        redis_reverse_file_data_pointer_set(store, 
                                            sector,
                                            counter, counter + superblock->block_size,
                                            file);
        D_PRINT64(counter);
        D_PRINT64(extent_new->ee_block);
        D_PRINT64(file);

        __reinspect_write(superblock, store, partition_offset,
                          sector, write_counter,
                          vmname);

        counter += superblock->block_size;        
        sector += sectors_per_block;
        
    }

    return EXIT_SUCCESS;
}

int __diff_ext4_extents(struct kv_store* store, char* vmname, uint64_t file,
                        uint64_t write_counter, uint8_t* newb, uint8_t* oldb,
                        uint64_t partition_offset,
                        struct super_info* superblock)
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
                                              superblock, partition_offset,
                                              write_counter, vmname);
                }
                    D_PRINT64(ext4_extent_index_leaf(*idx_new));
                    D_PRINT64(ext4_extent_index_leaf(*idx_old));
            }
            else
            {
                __ext4_new_extent_leaf_block(store, file,
                                          ext4_extent_index_leaf(*idx_new),
                                          superblock, partition_offset,
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
                    __ext4_new_extent(store, file, superblock, partition_offset,
                                      extent_new, vmname, write_counter);
                }
                else
                {
                    fprintf_light_cyan(stdout, "Extents exactly match.\n");
                }
            }
            else
            {
                __ext4_new_extent(store, file, superblock, partition_offset,
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

int __diff_data_ntfs(struct kv_store* store, struct ntfs_boot_file* bootf,
                     uint64_t partition_offset, uint8_t* data, uint64_t file)
{
    uint64_t data_offset = 0, real_size = 0, run_length = 0,
             run_length_bytes = 0, counter = 0, i;
    int64_t run_lcn = 0, run_lcn_bytes = 0, prev_lcn = 0;
    struct ntfs_standard_attribute_header sah;
    struct ntfs_non_resident_header nrh;

    if (ntfs_get_attribute(data, &sah, &data_offset, NTFS_DATA, ""))
    {
        fprintf_light_red(stderr, "Failed getting NTFS_DATA attr.\n");
        return EXIT_FAILURE;
    }

    if (sah.attribute_type != 0x80 &&
        sah.attribute_type != 0xA0)
    {
        fprintf_light_red(stderr, "Data handler, not a data attribute.\n");
        return EXIT_FAILURE;
    }
    
    if ((sah.flags & 0x0001) != 0x0000) /* check compressed */
    {
        fprintf_light_red(stderr, "NTFS: Error no support for compressed files"
                                  " yet.\n");
        return EXIT_FAILURE;
    }

    if ((sah.flags & 0x4000) != 0x0000) /* check encrypted */
    {
        fprintf_light_red(stderr, "NTFS: Error no support for encrypted files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    if ((sah.flags & 0x8000) != 0x0000) /* check sparse */
    {
        fprintf_light_red(stderr, "NTFS: Error no support for sparse files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    /* delete old list just in case (nuking for now) */
    redis_delete_key(store, REDIS_FILE_SECTORS_DELETE, file);

    if (sah.non_resident_flag)
    {
        /* if non-resident: walk runs, insert sectors */
        ntfs_read_non_resident_attribute_header(data, &data_offset, &nrh);
        ntfs_print_non_resident_header(&nrh);

        real_size = nrh.real_size;

        data_offset += nrh.data_run_offset - sizeof(sah) - sizeof(nrh);
        while (ntfs_parse_data_run(data, &data_offset, &run_length, &run_lcn) &&
               real_size > 0)
        {
            fprintf_light_blue(stderr, "got a sequence %d\n", counter++);
            run_length_bytes = run_length * bootf->bytes_per_sector * bootf->sectors_per_cluster;
            fprintf_light_red(stderr, "prev_lcn: %"PRIx64"\n", prev_lcn);
            fprintf_light_red(stderr, "run_lcn: %"PRIx64" (%"PRId64")\n",
                                      run_lcn, run_lcn);
            fprintf_light_red(stderr, "prev_lcn + run_lcn: %"PRIx64"\n",
                                       prev_lcn + run_lcn);
            run_lcn_bytes = ntfs_lcn_to_offset(bootf, partition_offset,
                                               prev_lcn + run_lcn);
            fprintf_light_blue(stderr, "run_lcn_bytes: %"PRIx64
                                       " run_length_bytes: %"PRIx64"\n",
                                       run_lcn_bytes,
                                       run_length_bytes);

            assert(prev_lcn + run_lcn >= 0);
            assert(prev_lcn + run_lcn < 26214400);
            assert(run_length_bytes > 0);

            for (i = 0; i < run_length_bytes / SECTOR_SIZE; i += 8)
            {
                redis_reverse_pointer_set(store, REDIS_FILE_SECTORS_INSERT,
                                          file,
                                          (int64_t) run_lcn_bytes / 512 + i);

            }
            
            real_size -= run_length_bytes;
            prev_lcn = prev_lcn + run_lcn;
            run_length = 0;
            run_length_bytes = 0;
            run_lcn = 0;
            run_lcn_bytes = 0;
        }
    }
    else
    {
        /* if resident: insert -1 */
        redis_reverse_pointer_set(store, REDIS_FILE_SECTORS_INSERT,
                                  file, (int64_t) -1);
    }

    return EXIT_SUCCESS;
}

int __diff_inodes_ntfs(uint8_t* write, struct kv_store* store,
                  char* vmname, uint64_t write_counter, char* pointer,
                  size_t write_len, struct ntfs_boot_file* bootf,
                  uint64_t partition_offset)
{
    uint64_t file = 0, lfiles = 0, i, offset;
    uint8_t** list;
    size_t len = 0, len2 = 4096;
    uint8_t *new, is_dir;
    char* path[len2];
    
    fprintf_light_white(stdout, "__diff_inodes_ntfs()\n");
    fprintf_light_white(stdout, "pointer: %s\n", pointer);

    strtok(pointer, ":");
    sscanf(strtok(NULL, ":"), "%"SCNu64, &lfiles);

    if (redis_list_get(store, REDIS_FILES_LGET, lfiles, &list, &len))
    {
        fprintf_light_red(stdout, "Error getting list of files from Redis.\n");
        return EXIT_FAILURE;
    }

    fprintf_light_white(stdout, "got inodes: %zd\n", len);

    for (i = 0; i < len; i++)
    {
        len2 = 4096;
        strtok((char*) (list)[i], ":");
        sscanf(strtok(NULL, ":"), "%"SCNu64, &file);
        fprintf(stdout, "getting path: %"PRIu64"\n", file);

        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "path",
                                 (uint8_t*) path, &len2))
        {
            fprintf_light_red(stdout, "Error getting path for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        path[len2] = '\0';

        len2 = sizeof(is_dir);
        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "is_dir",
                                 &is_dir, &len2)) 
        {

            fprintf_light_red(stdout, "Error getting is_dir for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }


        len2 = sizeof(offset);
        if (redis_hash_field_get(store, REDIS_FILE_SECTOR_GET, file, "inode_offset",
                                 (uint8_t*) &offset, &len2))
        {
            fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }

        new = &(write[offset]);

        /* update data pointers */
        if (!is_dir)
            __diff_data_ntfs(store, bootf, partition_offset, new, file);
        
        /* last step: overwrite old record with new */
        len2 = ntfs_file_record_size(bootf);
        if (redis_hash_field_set(store, REDIS_FILE_SECTOR_INSERT, file, "inode",
                                 (uint8_t*) new, len2))
        {
            fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                      "from Redis.\n", file);
            return EXIT_FAILURE;
        }
    }

    fprintf_light_cyan(stdout, "loaded: %zu elements\n", len);
    return EXIT_SUCCESS;
}

int __diff_inodes(uint8_t* write, struct kv_store* store,
                  char* vmname, uint64_t write_counter, char* pointer,
                  size_t write_len, struct super_info* superblock, uint64_t partition_offset)
{
    uint64_t file = 0, lfiles = 0, i, offset, last_sector;
    uint8_t** list;
    size_t len = 0, len2 = 4096;
    struct ext4_inode* new;
    char* channel = NULL, path[len2];
    bool is_dir, new_is_dir;
    uint64_t size, new_size;
    uint64_t mode, new_mode;
    uint64_t link_count, new_link_count;
    uint64_t uid, new_uid;
    uint64_t gid, new_gid;
    uint64_t atime, new_atime;
    uint64_t ctime, new_ctime;
    uint64_t mtime, new_mtime;
    
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

        GET_FIELD(REDIS_FILE_SECTOR_GET, file, is_dir, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, size, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, mode, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, link_count, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, uid, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, gid, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, atime, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, mtime, len2);
        GET_FIELD(REDIS_FILE_SECTOR_GET, file, ctime, len2);

        new = (struct ext4_inode*) &(write[offset]);

        new_is_dir = (new->i_mode & 0x4000) == 0x4000;
        new_size = ext4_file_size(*new);
        new_mode = new->i_mode;
        new_link_count = new->i_links_count;
        new_uid = new->i_uid;
        new_gid = new->i_gid;
        new_atime = new->i_atime;
        new_mtime = new->i_mtime;
        new_ctime = new->i_ctime;

        DIRECT_FIELD_COMPARE(is_dir, "file.is_dir", "metadata", BSON_BOOLEAN);
        DIRECT_FIELD_COMPARE(size, "file.size", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(mode, "file.mode", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(link_count, "file.link_count", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(uid, "file.uid", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(gid, "file.gid", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(atime, "file.atime", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(mtime, "file.mtime", "metadata", BSON_INT64);
        DIRECT_FIELD_COMPARE(ctime, "file.ctime", "metadata", BSON_INT64);

        fprintf_light_white(stdout, "Checking inode for file '%s', offset %"
                                    PRIu64"\n", path, offset);
        channel = construct_channel_name(vmname, path);
        fprintf_light_cyan(stdout, "channel: %s\n", channel);

        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, is_dir, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, size, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, mode, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, link_count, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, uid, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, gid, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, atime, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, mtime, len2);
        SET_FIELD(REDIS_FILE_SECTOR_INSERT, file, ctime, len2);

        if (((new->i_mode & 0x8000) == 0x8000 ||
             (new->i_mode & 0x4000) == 0x4000) &&
            !((new->i_mode & 0x6000) == 0x6000 ||
              (new->i_mode & 0xa000) == 0xa000))
        {
            //__diff_ext4_extents(store, vmname, file, write_counter, 
             //                   (uint8_t *) &(new->i_block[0]),
             //                   (uint8_t *) &(old->i_block[0]), partition_offset, super);
        }

        if (size < new_size)
        {
            if (redis_last_file_sector(store, file, &last_sector))
            {
                fprintf_light_red(stdout, "Error getting offset for file %"PRIu64
                                          "from Redis.\n", file);
                return EXIT_FAILURE;
            }
            fprintf_light_white(stdout, "Size mismatch. Checking for last "
                                        "block\n %"PRIu64" %"PRIu64" %"PRIu64,
                                        size, new_size, last_sector);

            __reinspect_write(superblock, store, partition_offset, last_sector,
                              write_counter, vmname);
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
                       struct super_info* superblock,
                       uint64_t partition_offset)
{
    size_t len = superblock->block_size, len2 = sizeof(uint64_t);
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
                        partition_offset, superblock);

    /* set new extent block */
    if (redis_hash_field_set(store, REDIS_EXTENT_SECTOR_INSERT, id, "data", write,
                             write_len))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


int __qemu_dispatch_write_ntfs(uint8_t* data,
                          struct kv_store* store, char* vmname,
                          uint64_t write_counter,
                          char* pointer, size_t len,
                          struct ntfs_boot_file* bootf,
                          uint64_t partition_offset,
                          uint64_t sector)
{
    D_PRINT64(partition_offset);
    fprintf_light_blue(stdout, "ntfs_dispatch pointer: %s\n", pointer);
    if (strncmp(pointer, "start", strlen("start")) == 0)
        __emit_file_bytes(data, store, vmname, write_counter, pointer, len,
                          sector);
    else if(strncmp(pointer, "fs", strlen("fs")) == 0)
        __diff_superblock_ntfs(data, store, vmname, write_counter, pointer, len);
    //else if(strncmp(pointer, "mbr", strlen("mbr")) == 0)
    //    __diff_mbr(data, store, vmname, pointer);
    //else if(strncmp(pointer, "lbgds", strlen("lbgds")) == 0)
    //    __diff_bgds(data, store, vmname, write_counter, pointer, len);
    else if(strncmp(pointer, "lfiles", strlen("lfiles")) == 0)
        __diff_inodes_ntfs(data, store, vmname, write_counter, pointer, len, bootf,
                      partition_offset);
    //else if(strncmp(pointer, "bgd", strlen("bgd")) == 0)
    //    __diff_bitmap(data, store, vmname, pointer);
    //else if(strncmp(pointer, "extent", strlen("extent")) == 0)
        //__diff_extent_tree(data, store, vmname, pointer, write_counter, len, 
        //                   super, partition_offset);
    //else if(strncmp(pointer, "dirdata", strlen("dirdata")) == 0)
    //    __diff_dir2_ntfs(data, store, vmname, write_counter, pointer, len,
    //                super, partition_offset);
    else
    {
        fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                      pointer);
    }
    return EXIT_SUCCESS;
}

int __qemu_dispatch_write(uint8_t* data,
                          struct kv_store* store, char* vmname,
                          uint64_t write_counter,
                          char* pointer, size_t len,
                          struct super_info* superblock,
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
        __diff_bgds(data, store, vmname, write_counter, pointer, len,
                    superblock, partition_offset);
    else if(strncmp(pointer, "lfiles", strlen("lfiles")) == 0)
        __diff_inodes(data, store, vmname, write_counter, pointer, len,
                      superblock, partition_offset);
    else if(strncmp(pointer, "bgd", strlen("bgd")) == 0)
        __diff_bitmap(data, store, vmname, pointer);
    else if(strncmp(pointer, "extent", strlen("extent")) == 0)
        __diff_extent_tree(data, store, vmname, pointer, write_counter, len, 
                           superblock, partition_offset);
    else if(strncmp(pointer, "dirdata", strlen("dirdata")) == 0)
        __diff_dir2(data, store, vmname, write_counter, pointer, len,
                    superblock, partition_offset);
    else
    {
        fprintf_light_red(stderr, "Redis returned unknown sector type [%s]\n",
                                                                      pointer);
    }
    return EXIT_SUCCESS;
}

int qemu_deep_inspect_ntfs(struct ntfs_boot_file* bootf,
                      struct qemu_bdrv_write* write,
                      struct kv_store* store, uint64_t write_counter,
                      char* vmname, uint64_t partition_offset)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t block_size = ntfs_cluster_size(bootf);
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
            __qemu_dispatch_write_ntfs(data, store, vmname, write_counter,
                                       (char *) result, (size_t) size, bootf,
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

int qemu_deep_inspect(struct super_info* superblock,
                      struct qemu_bdrv_write* write,
                      struct kv_store* store, uint64_t write_counter,
                      char* vmname, uint64_t partition_offset)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t size = 0;
    uint8_t* data;

    for (i = 0; i < write->header.nb_sectors; i += superblock->block_size / SECTOR_SIZE)
    {
        len = 1024;
        if (redis_sector_lookup(store, write->header.sector_num + i,
            result, &len))
        {
            fprintf_light_red(stderr, "Error doing sector lookup.\n");
            if ((write->header.nb_sectors - i) * SECTOR_SIZE < superblock->block_size)
            {
                size = (write->header.nb_sectors - i) * SECTOR_SIZE;
            }
            else
            {
                size = superblock->block_size;
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

            if ((write->header.nb_sectors - i) * SECTOR_SIZE < superblock->block_size)
            {
                size = (write->header.nb_sectors - i)* SECTOR_SIZE;
            }
            else
            {
                size = superblock->block_size;
            }

            D_PRINT64(partition_offset);
            __qemu_dispatch_write(data, store, vmname, write_counter,
                                  (char *) result, (size_t) size, superblock,
                                  partition_offset, write->header.sector_num);
        }
        else
        {
            fprintf_light_red(stderr, "Returned sector lookup empty.\n");
            if ((write->header.nb_sectors - i) * SECTOR_SIZE < superblock->block_size)
            {
                size = (write->header.nb_sectors - i) * SECTOR_SIZE;
            }
            else
            {
                size = superblock->block_size;
            }

            redis_enqueue_pipelined(store, write->header.sector_num + i,
                                    &(write->data[i*SECTOR_SIZE]),
                                    size);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int qemu_get_superinfo(struct kv_store* store,
                        struct super_info* super_info,
                        uint64_t fs_id)
{
    size_t len;
    uint64_t superblock_sector, superblock_offset, block_size,
             blocks_per_group, inodes_per_group, inode_size;

    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, superblock_sector, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, superblock_offset, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, block_size, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, blocks_per_group, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, inodes_per_group, len);
    GET_FIELD(REDIS_SUPERBLOCK_SECTOR_GET, fs_id, inode_size, len);

    super_info->superblock_sector    =     superblock_sector;
    super_info->superblock_offset    =     superblock_offset;
    super_info->block_size           =     block_size;
    super_info->blocks_per_group     =     blocks_per_group;
    super_info->inodes_per_group     =     inodes_per_group;
    super_info->inode_size           =     inode_size;

    return EXIT_SUCCESS;
}

int qemu_get_bootf(struct kv_store* store,
                   struct ntfs_boot_file* bootf,
                   uint64_t fs_id)
{
    size_t len = sizeof(struct ntfs_boot_file);

    if (redis_hash_field_get(store, REDIS_SUPERBLOCK_SECTOR_GET,
                             fs_id, "superblock", (uint8_t*) bootf,
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


enum SECTOR_TYPE qemu_infer_ntfs_sector_type(struct ntfs_boot_file* bootf,
                                        struct qemu_bdrv_write* write,
                                        struct kv_store* store)
{
    uint64_t i;
    uint8_t result[1024];
    size_t len = 1024;
    uint64_t block_size = ntfs_cluster_size(bootf);

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

int __deserialize_bitarray(struct bson_info* bson, struct kv_store* store)
{
    struct bson_kv value1, value2;

    while (bson_deserialize(bson, &value1, &value2))
    {
        if (strcmp(value1.key, "bitarray") == 0)
        {
            if (redis_metadata_set(store, value1.data, value1.size))
            {
                fprintf_light_red(stderr, "Error setting metadata field.\n");
                return EXIT_FAILURE;
            }
        }
        else
        {
            fprintf_light_red(stderr, "Unkown field for metadata filter: %s\n",
                                                                   value1.key);
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
        else if (strcmp(value1.key, "files") == 0)
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

                if (redis_binary_insert(store, REDIS_DIR_FILES_INSERT, sector,
                                        (const uint8_t*) value1.data,
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
                                       (int64_t) *((int32_t *) value1.data));
                redis_reverse_file_data_pointer_set(store, 
                        (int64_t) *((int32_t*)value1.data),
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

int qemu_load_md_filter(FILE* index, struct bitarray** bits)
{
    struct bson_kv value1, value2;
    struct bson_info* bson = bson_init();

    while (bson_readf(bson, index) == 1)
    {
        if (bson_deserialize(bson, &value1, &value2) != 1)
            break;
        
        if (strcmp(value1.key, "type") != 0)
        {
            fprintf_light_red(stderr, "Document missing 'type' field.\n");
            break;
        }
       
        if (strcmp(value1.data, "metadata_filter") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a bitarray record "
                                         "--\n");
            if (bson_deserialize(bson, &value1, &value2) != 1)
                return EXIT_FAILURE;

            if (strcmp(value1.key, "bitarray") == 0)
            {
                *bits = bitarray_init_data((uint8_t*) value1.data, value1.size);
                return EXIT_SUCCESS;
            }
            else
            {
                fprintf_light_red(stderr, "Unexpected field in MD record.\n");
                break;
            }
        }
    }
    
    return EXIT_FAILURE;
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
        else if (strcmp(value1.data, "metadata_filter") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a bitarray record "
                                         "--\n");
            if (__deserialize_bitarray(bson, store))
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
