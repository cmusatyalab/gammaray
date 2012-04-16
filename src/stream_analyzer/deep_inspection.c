#include "deep_inspection.h"
#include "bson.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

void qemu_parse_header(uint8_t* event_stream, struct qemu_bdrv_write* write)
{
    write->header = *((struct qemu_bdrv_write_header*) event_stream);
}

int __deserialize_mbr(FILE* index, struct bson_info* bson, struct mbr* mbr)
{
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "gpt") != 0)
        return EXIT_FAILURE;

    mbr->gpt = *((bool*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    mbr->sector = *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "active_partitions") != 0)
        return EXIT_FAILURE;

    mbr->active_partitions = *((uint32_t*) value1.data);

    return EXIT_SUCCESS;
}

int __deserialize_partition(FILE* index, struct bson_info* bson,
                            struct mbr* mbr)
{
    struct partition pt;
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "pte_num") != 0)
        return EXIT_FAILURE;

    pt.pte_num = *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "partition_type") != 0)
        return EXIT_FAILURE;

    pt.partition_type = *((uint32_t*) value1.data);    
    
    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "first_sector_lba") != 0)
        return EXIT_FAILURE;

    pt.first_sector_lba = *((uint32_t*) value1.data);    

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "final_sector_lba") != 0)
        return EXIT_FAILURE;

    pt.final_sector_lba = *((uint32_t*) value1.data);    
    
    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "sector") != 0)
        return EXIT_FAILURE;

    pt.sector = *((uint32_t*) value1.data);

    linkedlist_append(mbr->pt, &pt, sizeof(pt));

    return EXIT_SUCCESS;
}

int __deserialize_ext2_fs(FILE* index, struct bson_info* bson,
                          struct partition* pt)
{
    struct ext2_fs fs;
    struct bson_kv value1, value2;

    if (bson_readf(bson, index) != 1)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "fs_type") != 0)
        return EXIT_FAILURE;

    fs.fs_type = *((uint32_t*) value1.data);

    if (fs.fs_type != 0)
        return EXIT_FAILURE;

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "mount_point") != 0)
        return EXIT_FAILURE;

    fs.mount_point = ((char*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "num_block_groups") != 0)
        return EXIT_FAILURE;

    fs.num_block_groups = *((uint32_t*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;
    
    if (strcmp(value1.key, "superblock") != 0)
        return EXIT_FAILURE;

    fs.superblock = *((struct ext2_superblock*) value1.data);

    if (bson_deserialize(bson, &value1, &value2) != 1)
        return EXIT_FAILURE;

    pt->fs = fs;

    return EXIT_SUCCESS;
}

int qemu_load_index(FILE* index, struct mbr* mbr)
{
    uint64_t i, j;
    struct bson_info* bson;

    bson = bson_init();

    /* mbr */
    if (__deserialize_mbr(index, bson, mbr))
    {
        fprintf_light_red(stderr, "Error loading MBR document.\n");
        return EXIT_FAILURE;
    }

    mbr->pt = linkedlist_init();

    /* partition entries */
    for (i = 0; i < mbr->active_partitions; i++)
    {
        if (__deserialize_partition(index, bson, mbr))
        {
            fprintf_light_red(stderr, "Error loading partition document.\n");
            return EXIT_FAILURE;
        }

        if (__deserialize_ext2_fs(index, bson,
                                  (struct partition*) linkedlist_tail(mbr->pt)))
        {
            fprintf_light_red(stderr, "Error loading ext2_fs document.\n");
        }
    } 

    bson_cleanup(bson);

    return EXIT_SUCCESS;
}
