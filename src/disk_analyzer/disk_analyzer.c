/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a raw disk image and produce summary datastructures of   *
 *          the partition table, and file system metadata.                   *
 *                                                                           *
 *****************************************************************************/


#define UINT_16(s) *((uint16_t *) &s)
#define UINT_32(i) *((uint32_t *) &i)

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "color.h"

void print_partition_type(uint8_t type)
{
    char* LUT[] = { "Empty","","","","","Extended","","HPFS/NTFS","","","","W95 FAT32","","","","", /* 0x00 - 0x0f */
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

    fprintf_light_white(stdout, "Partition Type: %s\n", LUT[type]);

    return;
}

uint8_t get_sector(uint8_t byte)
{
    return 0x3f & byte;
}

uint16_t get_cylinder(uint8_t* bytes)
{
    uint8_t b1 = bytes[0];
    uint8_t b2 = bytes[1];
    /* grab bits 9-0 */
    uint16_t cylinder = (b1 & 0xc0) << 2;
    return cylinder | b2;
}

/* prints partition entry according to Wikipedia:
 * http://en.wikipedia.org/wiki/Master_boot_record */
void print_partition(uint8_t* start)
{
    fprintf_blue(stdout, "Status [0x80 bootable, 0x00 non-bootable]: 0x%.2"
                         PRIx8"\n",
                         start[0]);
    fprintf_blue(stdout, "Partition Type: 0x%.2"
                    PRIx8"\n",
                    start[4]);
    
    print_partition_type(start[4]);

    /* check it partition entry is being used */
    if (start[4] == 0x00) return;
    
    fprintf_blue(stdout, "Start Head: 0x%.2"
                    PRIx8"\n",
                    start[1]);
    fprintf_blue(stdout, "Start Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(start[2]));
    fprintf_blue(stdout, "Start Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(start[2])));
    fprintf_blue(stdout, "End Head: 0x%.2"
                    PRIx8"\n",
                    start[5]);
    fprintf_blue(stdout, "End Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(start[6]));
    fprintf_blue(stdout, "End Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(start[6])));
    fprintf_green(stdout, "First Sector LBA: 0x%.8"
                    PRIx32"\n",
                    UINT_32(start[8]));
    fprintf_green(stdout, "Number of Sectors: 0x%.8"
                    PRIx32"\n",
                    UINT_32(start[12]));

    return;
}

int analyze_mbr(FILE * mbrfd, long int offset)
{
    fprintf_light_cyan(stdout, "\n\nAnalyzing Boot Sector at Offset 0x%lx\n\n",
                               offset);
    uint8_t mbr[512];
    /* read Master Boot Record (MBR) */

    if (fseek(mbrfd, offset, 0))
    {
        fprintf_light_red(stderr, "Error seeking to position 0x%lx.\n", offset);
    }
    
    size_t read = fread(mbr, 1, 512, mbrfd);

    if (read < 512)
    {
        fprintf_light_red(stderr, "Error reading MBR from raw disk file.\n");
        return EXIT_FAILURE;
    }

    /* Taking apart according to Wikipedia:            
     * http://en.wikipedia.org/wiki/Master_boot_record */
    fprintf_yellow(stdout, "Disk Signature [optional]: 0x%.8"PRIx32"\n",
                            UINT_32(mbr[440]));

    fprintf_yellow(stdout, "Position 444 [0x0000]: 0x%.4"PRIx16"\n",
                           UINT_16(mbr[444]));
    
    if (mbr[510] == 0x55 && mbr[511] == 0xaa)
    {
        fprintf_light_green(stdout, "Verifying MBR Signature [0x55 0xaa]: "
                                    "0x%.2"PRIx8" 0x%.2"
                                    PRIx8"\n\n",
                                    mbr[510],
                                    mbr[511]);
    }
    else
    {
        fprintf_light_red(stdout, "Verifying MBR Signature [0x55 0xaa]: 0x%.2"
                                  PRIx8" 0x%.2"PRIx8"\n\n",
                                  mbr[510],
                                  mbr[511]);
        return EXIT_FAILURE;
    }

    /* read all 4 partition table entries */
    fprintf_light_yellow(stdout, "\nChecking partition table entry 1.\n");
    print_partition(&(mbr[446]));
    fprintf_light_yellow(stdout, "\nChecking partition table entry 2.\n");
    print_partition(&(mbr[462]));
    fprintf_light_yellow(stdout, "\nChecking partition table entry 3.\n");
    print_partition(&(mbr[480]));
    fprintf_light_yellow(stdout, "\nChecking partition table entry 4.\n");
    print_partition(&(mbr[496]));

    return EXIT_SUCCESS;
}

/* main thread of execution */
int main(int argc, char* args[])
{
    fprintf_blue(stdout, "Raw Disk Analyzer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: ./%s <raw disk file>\n", args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing Disk: %s\n\n", args[1]);

    FILE* mbrfd = fopen(args[1], "r");
    
    if (mbrfd == NULL)
    {
        fprintf_light_red(stderr, "Error opening raw disk file."
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    analyze_mbr(mbrfd, 0x0);

    return EXIT_SUCCESS;
}
