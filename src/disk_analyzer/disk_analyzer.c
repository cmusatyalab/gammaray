/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a raw disk image and produce summary datastructures of   *
 *          the partition table, and file system metadata.                   *
 *                                                                           *
 *****************************************************************************/


#define UINT_8(b) ((uint8_t) b)
#define UINT_16(s) *((uint16_t *) &s)
#define UINT_32(i) *((uint32_t *) &i)

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void print_partition_type(char type)
{
    char* LUT[] = { "","","","","","","","","","","","W95 FAT32","","","","", /* 0x00 - 0x0f */
                    "","","","","","","","","","","","","","","","", /* 0x10 - 0x1f */
                    "","","","","","","","","","","","","","","","", /* 0x20 - 0x2f */
                    "","","","","","","","","","","","","","","","", /* 0x30 - 0x3f */
                    "","","","","","","","","","","","","","","","", /* 0x40 - 0x4f */
                    "","","","","","","","","","","","","","","","", /* 0x50 - 0x5f */
                    "","","","","","","","","","","","","","","","", /* 0x60 - 0x6f */
                    "","","","","","","","","","","","","","","","", /* 0x70 - 0x7f */
                    "","","Linux Swap","Linux","","Linux Extended","","","","","","","","","Linux LVM","", /* 0x80 - 0x8f */
                    "","","","","","","","","","","","","","","","", /* 0x90 - 0x9f */
                    "","","","","","","","","","","","","","","","HFS / HFS+", /* 0xa0 - 0xaf */
                    "","","","","","","","","","","","","","","","", /* 0xb0 - 0xbf */
                    "","","","","","","","","","","","","","","","", /* 0xc0 - 0xcf */
                    "","","","","","","","","","","","","","","","", /* 0xd0 - 0xdf */
                    "","","","","","","","","","","","","","","GPT","EFI", /* 0xe0 - 0xef */
                    "","","","","","","","","","","","","","","",""  /* 0xf0 - 0xff */
                  };
    fprintf(stdout, "Partition Type: %s\n", LUT[(uint8_t) type]);
    return;
}

/* prints partition entry according to Wikipedia:
 * http://en.wikipedia.org/wiki/Master_boot_record */
void print_partition(char* start)
{
    fprintf(stdout, "Status [0x80 bootable, 0x00 non-bootable]: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[0]));
    if (UINT_8(start[0]) == 0x00) return;
    fprintf(stdout, "Start Head: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[1]));
    fprintf(stdout, "Start Sector: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[2]));
    fprintf(stdout, "Start Cylinder: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[3]));
    fprintf(stdout, "Partition Type: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[4]));
    fprintf(stdout, "End Head: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[5]));
    fprintf(stdout, "End Sector: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[6]));
    fprintf(stdout, "End Cylinder: 0x%.2"
                    PRIx8"\n",
                    UINT_8(start[7]));
    fprintf(stdout, "First Sector LBA: 0x%.8"
                    PRIx32"\n",
                    UINT_32(start[8]));
    fprintf(stdout, "Number of Sectors: 0x%.8"
                    PRIx32"\n",
                    UINT_32(start[12]));

    print_partition_type(start[4]);
    return;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    char mbr[512];
    fprintf(stdout, "Raw Disk Analyzer -- By: Wolfgang Richter "
                    "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf(stderr, "Usage: ./%s <raw disk file>\n", args[0]);
        return EXIT_FAILURE;
    }

    /* read Master Boot Record (MBR) */
    fprintf(stdout, "Analyzing Disk: %s\n", args[1]);

    FILE* mbrfd = fopen(args[1], "r");
    
    if (mbrfd == NULL)
    {
        fprintf(stderr, "Error opening raw disk file.  Does it exist?\n");
        return EXIT_FAILURE;
    }

    size_t read = fread(mbr, 1, 512, mbrfd);

    if (read < 512)
    {
        fprintf(stderr, "Error reading MBR from raw disk file.\n");
        return EXIT_FAILURE;
    }

    /* Taking apart according to Wikipedia:            
     * http://en.wikipedia.org/wiki/Master_boot_record */
    fprintf(stdout, "Disk Signature [optional]: 0x%.8"PRIx32"\n",
                    UINT_32(mbr[440]));

    fprintf(stdout, "Position 444 [0x0000]: 0x%.4"PRIx16"\n",
                    UINT_16(mbr[444]));
    
    fprintf(stdout, "Verifying MBR Signature [0x55 0xaa]: 0x%.2"PRIx8" 0x%.2"
                    PRIx8"\n",
                    UINT_8(mbr[510]),
                    UINT_8(mbr[511]));

    /* read all 4 partition table entries */
    print_partition(&(mbr[446]));
    print_partition(&(mbr[462]));
    print_partition(&(mbr[480]));
    print_partition(&(mbr[496]));

    return EXIT_SUCCESS;
}
