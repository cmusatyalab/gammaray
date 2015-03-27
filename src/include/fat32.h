#ifndef __GAMMARAY_DISK_CRAWLER_FAT32_H
#define __GAMMARAY_DISK_CRAWLER_FAT32_H

#include <time.h>

#include "gray-crawler.h"

#define FAT32_EOC 0x0FFFFFFF
#define FAT32_BPB 0x0FFFFFF8

struct fat32_volumeID {
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t num_reserved_sectors;
    uint8_t num_fats;
    uint32_t sectors_per_fat;
    uint32_t root_dir_first_cluster;
    uint16_t signature;
};

struct fat32_file {
    char* name;
    char* path;
    bool is_dir;
    uint32_t cluster_num;
    uint32_t dir_cluster_num;
    uint64_t dir_cluster_addr;
    uint64_t inode_sector;
    uint64_t inode_offset;
    uint32_t size;
    time_t crtime;
    time_t latime;
    time_t lwtime;
};

int fat32_probe(int disk, struct fs* fs);
int fat32_serialize(int disk, struct fs* fs, int serializef);
int fat32_cleanup(struct fs* fs);

#endif
