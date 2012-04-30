#define _FILE_OFFSET_BITS 64

#include "color.h"
#include "ntfs.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512

void print_standard_attribute_header(struct standard_attribute_header* sah)
{
    fprintf_light_green(stdout, "attribute_type: 0x%"PRIx32"\n", sah->attribute_type);
}

void print_standard_information(struct standard_information* si)
{
    fprintf_yellow(stdout, "c_time: %"PRIu64"\n", si->c_time);
    fprintf_yellow(stdout, "a_time: %"PRIu64"\n", si->a_time);
    fprintf_yellow(stdout, "m_time: %"PRIu64"\n", si->m_time);
    fprintf_yellow(stdout, "r_time: %"PRIu64"\n", si->r_time);
}

void print_file_record(struct file_record* rec)
{
    uint8_t* magic = (uint8_t*) &(rec->magic);
    fprintf_light_red(stdout, "file_record[0].magic: %c%c%c%c\n", magic[0],
                                                                  magic[1],
                                                                  magic[2],
                                                                  magic[3]);
    fprintf_yellow(stdout, "flags: %"PRIx16"\n", rec->flags);
}

int ntfs_probe(FILE* disk, int64_t partition_offset,
               struct ntfs_superblock* superblock)
{
    struct file_record rec;
    uint8_t* magic = (uint8_t*) &(rec.magic);

    if (fseeko(disk, partition_offset + SECTOR_SIZE*16, SEEK_SET))
    {
        fprintf_light_red(stderr, "Error seeking to partition offset and $MFT "
                                  "position while NTFS probing.\n");
        return EXIT_FAILURE;
    }

    if (fread(&rec, 1, sizeof(rec), disk) != sizeof(rec))
    {
        fprintf_light_red(stderr, "Error reading FILE Record.\n");
        return EXIT_FAILURE;
    }

    if (memcmp(magic, "FILE", 4) != 0 && 
        memcmp(magic, "BAAD", 4) != 0)
    {
        fprintf_light_red(stderr, "NTFS probe failed.\n");
        return EXIT_FAILURE;
    }

    print_file_record(&rec);

    return EXIT_SUCCESS;
}
