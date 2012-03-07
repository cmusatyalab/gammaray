#include <string.h>

#include "mbr.h"

char* MBR_PT_LUT[] = { "Empty","","","","","Extended","","HPFS/NTFS","","","","W95 FAT32","","","","", /* 0x00 - 0x0f */
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

int print_partition_type(uint8_t type)
{
    fprintf_light_magenta(stdout, "Partition Type: %s\n", MBR_PT_LUT[type]);
    return -1;
}

uint8_t get_sector(uint8_t byte)
{
    return 0x3f & byte; /* bits 5-0 in second byte of chs */
}

uint16_t get_cylinder(uint8_t bytes[2])
{
    uint8_t b1 = bytes[0];
    uint8_t b2 = bytes[1];
    /* grab bits 9-0 */
    uint16_t cylinder = (b1 & 0xc0) << 2;
    return cylinder | b2;
}

/* prints partition entry according to Wikipedia:
 * http://en.wikipedia.org/wiki/Master_boot_record */
int print_partition(struct partition_table_entry pte)
{
    fprintf_blue(stdout, "Status [0x80 bootable, 0x00 non-bootable]: 0x%.2"
                         PRIx8"\n",
                         pte.status);
    fprintf_blue(stdout, "Partition Type: 0x%.2"
                    PRIx8"\n",
                    pte.partition_type);
    
    print_partition_type(pte.partition_type);

    /* check it partition entry is being used */
    if (pte.partition_type == 0x00) return -1;
    
    fprintf_blue(stdout, "Start Head: 0x%.2"
                    PRIx8"\n",
                    pte.start_chs[0]);
    fprintf_blue(stdout, "Start Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(pte.start_chs[1]));
    fprintf_blue(stdout, "Start Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(pte.start_chs[1])));
    fprintf_blue(stdout, "End Head: 0x%.2"
                    PRIx8"\n",
                    pte.end_chs[0]);
    fprintf_blue(stdout, "End Sector: 0x%.2"
                    PRIx8"\n",
                    get_sector(pte.end_chs[1]));
    fprintf_blue(stdout, "End Cylinder: 0x%.3"
                    PRIx16"\n",
                    get_cylinder(&(pte.end_chs[1])));
    fprintf_green(stdout, "First Sector LBA: 0x%.8"
                    PRIx32"\n",
                    pte.first_sector_lba);
    fprintf_green(stdout, "Number of Sectors: 0x%.8"
                    PRIx32"\n",
                    pte.sector_count);
    return 0;
}

int print_mbr(struct mbr mbr)
{
    fprintf_light_cyan(stdout, "\n\nAnalyzing Boot Sector\n");

    /* Taking apart according to Wikipedia:            
     * http://en.wikipedia.org/wiki/Master_boot_record */
    fprintf_yellow(stdout, "Disk Signature [optional]: 0x%.8"PRIx32"\n",
                            mbr.disk_signature);

    fprintf_yellow(stdout, "Position 444 [0x0000]: 0x%.4"PRIx16"\n",
                           mbr.reserved);
    
    if (mbr.signature[0] == 0x55 && mbr.signature[1] == 0xaa)
    {
        fprintf_light_green(stdout, "Verifying MBR Signature [0x55 0xaa]: "
                                    "0x%.2"PRIx8" 0x%.2"
                                    PRIx8"\n\n",
                                    mbr.signature[0],
                                    mbr.signature[1]);
    }
    else
    {
        fprintf_light_red(stdout, "Verifying MBR Signature [0x55 0xaa]: 0x%.2"
                                  PRIx8" 0x%.2"PRIx8"\n\n",
                                  mbr.signature[0],
                                  mbr.signature[1]);
        return -1; 
    }

    /* read all 4 partition table entries */
    fprintf_light_yellow(stdout, "\nChecking partition table entry 0.\n");
    print_partition(mbr.pt[0]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 1.\n");
    print_partition(mbr.pt[1]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 2.\n");
    print_partition(mbr.pt[2]);
    fprintf_light_yellow(stdout, "\nChecking partition table entry 3.\n");
    print_partition(mbr.pt[3]);

    return 0;
}

int parse_mbr(FILE* disk, struct mbr* mbr)
{
    if (fread(mbr, 1, sizeof(struct mbr), disk) < sizeof(struct mbr))
    {
        fprintf_light_red(stderr, "Error reading MBR from raw disk file.\n");
        return -1;
    }

    if (mbr->signature[0] != 0x55 || mbr->signature[1] != 0xaa)
    {
        fprintf_light_red(stderr, "Bad MBR signature: "
                                  "%.2"PRIx8" %.2"PRIx8".\n",
                                  mbr->signature[0],
                                  mbr->signature[1]);
        return -1;
    }

    return 0;
}

/* REENTRANT */
int64_t mbr_partition_offset(struct mbr mbr, int pte)
{
    /* linux partition match */
    if (mbr.pt[pte].partition_type == 0x83)
    {
        return SECTOR_SIZE*mbr.pt[pte].first_sector_lba;
    }

    return 0;
}

int print_partition_sectors(struct partition_table_entry pte)
{
    fprintf_yellow(stdout, "Partition Sector Start %"
                            PRIu32"\nPartition Sector End %"PRIu32"\n",
                            pte.first_sector_lba,
                            pte.first_sector_lba +
                            pte.sector_count);
    return 0;
}

int mbr_print_numbers(struct mbr mbr)
{
    fprintf_yellow(stdout, "MBR Start Sector 0\n");
    fprintf_yellow(stdout, "MBR End Sector 0\n");
    return 0;
}

int mbr_get_partition_table_entry(struct mbr mbr, int pte_num,
                                  struct partition_table_entry* pte)
{
    memcpy(pte, &mbr.pt[pte_num], sizeof(struct partition_table_entry));
    return 0;
}
