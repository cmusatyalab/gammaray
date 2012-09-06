#include "mbr.h"
#include "ebr.h"
#include "util.h"

int ebr_probe(FILE* disk, int64_t partition_offset,
              struct disk_mbr* ebr)
{
    if (partition_offset == 0)
    {
        fprintf_light_red(stderr, "EBR probe failed on partition at offset: "
                                  "0x%.16"PRIx64".\n", partition_offset);
        return -1;
    }

    if (fseeko(disk, partition_offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%.16"PRIx64".\n",
                                  partition_offset);
        return -1;
    }

    if (fread(ebr, 1, sizeof(struct disk_mbr), disk) !=
        sizeof(struct disk_mbr))
    {
        fprintf_light_red(stderr, 
                          "Error while trying to read EBR.\n");
        return -1;
    }

    if (ebr->signature[0] != 0x55 || ebr->signature[1] != 0xaa)
    {
        fprintf_light_red(stderr, "Bad EBR signature: "
                                  "%.2"PRIx8" %.2"PRIx8".\n",
                                  ebr->signature[0],
                                  ebr->signature[1]);
        return -1;
    }

    return 0;
}
