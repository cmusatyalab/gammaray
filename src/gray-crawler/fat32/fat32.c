#define _LARGEFILE64_SOURCE

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bitarray.h"
#include "bson.h"
#include "color.h"
#include "fat32.h"

#define SECTOR_SIZE 512

void print_hex_memory(void *mem, int n);
int fat32_probe(int disk, struct fs* fs)
{
  struct fat32_volumeID* volumeID;
  fs->fs_info = malloc(sizeof(struct fat32_volumeID));

  if (fs->fs_info == NULL)
  {
      fprintf_light_red(stderr, "Error allocating space for "
                                "'struct fat32_volumeID'.\n");
      return -1;
  }

  volumeID = (struct fat32_volumeID*) fs->fs_info;

  if (fs->pt_off == 0)
  {
      fprintf_light_red(stderr, "fat32 probe failed on partition at offset: "
                                "0x%.16"PRIx64".\n", fs->pt_off);
      return -1;
  }
  
  //fprintf_light_white(stdout, "pt_off: %016llX\n", fs->pt_off);
  fprintf_light_white(stdout, "pt_off: 0x%.16"PRIx64".\n", fs->pt_off);

  //fseeko(disk, fs->pt_off + 0x0B, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x0B), SEEK_SET);
  //if (fread((void*)&volumeID->bytes_per_sector, 1, sizeof(uint16_t), disk) !=
  //      sizeof(uint16_t))
  if (read(disk, (void*)&volumeID->bytes_per_sector, sizeof(uint16_t)) != 
          sizeof(uint16_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 bytes_per_sector.\n");
        return -1;
  }

  //fseeko(disk, fs->pt_off + 0x0D, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x0D), SEEK_SET);
  //if (fread((void*)&volumeID->sectors_per_cluster, 1, sizeof(uint8_t), disk) !=
  //      sizeof(uint8_t))
  if (read(disk, (void*)&volumeID->sectors_per_cluster, sizeof(uint8_t)) != 
          sizeof(uint8_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 sectors_per_cluster.\n");
        return -1;
  }

  printf("SectorsPerCluster %" PRIu8 "\n",volumeID->sectors_per_cluster);
  //fseeko(disk, fs->pt_off + 0x0E, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x0E), SEEK_SET);
  //if (fread((void*)&volumeID->num_reserved_sectors, 1, sizeof(uint16_t), disk) !=
  //      sizeof(uint16_t))
  if (read(disk, (void*)&volumeID->num_reserved_sectors, sizeof(uint16_t)) != 
          sizeof(uint16_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 num_reserved_sectors.\n");
        return -1;
  }

  printf("NumReservedSectors %" PRIu16 "\n",volumeID->num_reserved_sectors);

  //fseeko(disk, fs->pt_off + 0x10, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x10), SEEK_SET);
  //if (fread((void*)&volumeID->num_fats, 1, sizeof(uint8_t), disk) !=
  //      sizeof(uint8_t))
  if (read(disk, (void*)&volumeID->num_fats, sizeof(uint8_t)) != 
          sizeof(uint8_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 num_fats.\n");
        return -1;
  }
  fprintf_light_white(stdout, "fat32 numfats: %x\n", volumeID->num_fats);
  //fseeko(disk, fs->pt_off + 0x24, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x24), SEEK_SET);
  //if (fread((void*)&volumeID->sectors_per_fat, 1, sizeof(uint32_t), disk) !=
  //      sizeof(uint32_t))
  if (read(disk, (void*)&volumeID->sectors_per_fat, sizeof(uint32_t)) != 
          sizeof(uint32_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 sectors_per_fat.\n");
        return -1;
  }

  printf("SectorsPerFat %" PRIu32 "\n",volumeID->sectors_per_fat);
  //fseeko(disk, fs->pt_off + 0x2C, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x2C), SEEK_SET);
  //if (fread((void*)&volumeID->root_dir_first_cluster, 1, sizeof(uint32_t), disk) !=
  //      sizeof(uint32_t))
  if (read(disk, (void*)&volumeID->root_dir_first_cluster, sizeof(uint32_t)) != 
          sizeof(uint32_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 root_dir_first_cluster.\n");
        return -1;
  }
  printf("RootDirFstCluster%" PRIu32 "\n",volumeID->root_dir_first_cluster);

  char *volLab = calloc(1, 12);
  //fseeko(disk, fs->pt_off + 71, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 71), SEEK_SET);
  //if (fread((void*)volLab, 1, 11, disk) != 11)
  if (read(disk, (void*)volLab, 11) != 11)
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 signatureeee.\n");
        return -1;
  }
  print_hex_memory(volLab, 11);

  //fseeko(disk, fs->pt_off + 0x1FE, SEEK_SET);
  lseek64(disk, (off64_t) (fs->pt_off + 0x1FE), SEEK_SET);
  //if (fread((void*)&volumeID->signature, 1, sizeof(uint32_t), disk) !=
  //      sizeof(uint32_t))
  if (read(disk, (void*)&volumeID->signature, sizeof(uint32_t)) != 
          sizeof(uint32_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 signature.\n");
        return -1;
  }

  if (volumeID->signature != 0xAA55)
  {
    fprintf_light_red(stderr, "Fat32 signature does not match 0xAA55.\n");
    return -1;
  }

  return 0;
}

void print_hex_memory(void *mem, int n) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<n;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}

int64_t get_cluster_addr(struct fs* fs, uint32_t cluster_number) {  
  struct fat32_volumeID* volID = fs->fs_info;
  int64_t cluster_begin_lba = (int64_t)volID->num_reserved_sectors + (volID->num_fats * volID->sectors_per_fat);
  printf("cluster_begin_lba %" PRId64 "\n", cluster_begin_lba);
  printf("fs PTOFF %" PRId64 "\n", fs->pt_off);
  /* TODO: Define sector size. */
  return fs->pt_off + (int64_t)512*(cluster_begin_lba + (cluster_number - 2) * volID->sectors_per_cluster);
}

uint32_t get_fat_entry(int disk, int cluster_num, struct fs* fs) {
  struct fat32_volumeID* volID = fs->fs_info;
  
  int64_t fat_begin = fs->pt_off + volID->num_reserved_sectors * SECTOR_SIZE;
  int64_t fat_entry_addr = fat_begin + (cluster_num * 4);
  //fseeko(disk, fat_entry_addr, SEEK_SET);
  lseek64(disk, (off64_t) (fat_entry_addr), SEEK_SET);
  uint32_t result;
  //if (fread((void*)&result, 1, 4, disk) != 4)
  if (read(disk, (void*)&result, 4) != 4)
  {
    fprintf_light_red(stderr, "Error while trying to read fat entry.\n");
    return -1;
  }
  return result;
}

char* read_name_long_entry(unsigned char* entry) 
{
  char *name = calloc(1, 14);
  int idx; int i;
  for (i = 0; i < 13; i++) 
  {
    if (i < 5) {
      idx = 2 * i + 1;
    } else if (i < 11) {
      idx = 2 * (i - 5) + 14;
    } else {
      idx = 2 * (i - 11) + 28;
    }
    memcpy(name + i, entry + idx, 1);
    if (!*(entry + idx)) break;
  }
  return name;
}

char* read_long_entries(int disk, unsigned char* last_entry, int* offset)
{
  bool fst_long_entry = false;
  unsigned char* entry = last_entry;
  char* name = NULL;
  while (!fst_long_entry) 
  {
    if (!entry[0]) break;
    char* entry_name = read_name_long_entry(entry);
    if (!name) 
    {
      name = entry_name;
    }
    else 
    {
      char* temp = name;
      name = calloc(1, strlen(name) + strlen(entry_name) + 1);
      strcpy(name, entry_name); strcat(name, temp);
      free(temp);
    }
    if (!((entry[0] & 0xF) ^ 0x1))
    {
      break;
    } 
    if (read(disk, (void*)entry, 32) != 32)
    {
      fprintf_light_red(stderr, "Error while trying to read record.\n");
      return NULL;
    }
    *offset += 32;
  }
  return name;
}

char* read_short_entry(unsigned char* entry) 
{
  char* name = calloc(1, 12);
  memcpy(name, entry, 11);
  return name;
}

void read_dir_cluster(char* path, int disk, uint32_t cluster_num, struct fs* fs, int serializef) 
{
  int64_t cluster_addr = get_cluster_addr(fs, cluster_num); int offset = 0;
  unsigned char* entry = calloc(1, 32); 
  lseek64(disk, (off64_t) (cluster_addr), SEEK_SET);
  struct fat32_volumeID* volID = fs->fs_info;
  char* long_name = NULL;
  while (true) 
  {
    if (read(disk, (void*)entry, 32) != 32)
    {
      fprintf_light_red(stderr, "Error while trying to read record.\n");
        return;
    }
    offset += 32;
    //print_hex_memory(entry, 32);
    
    if (!(entry[0] ^ (unsigned char)0xe5))
    {
      //printf("Free Entry!\n");
      continue;
    }
    if (!entry[0]) 
    {
      printf("End of Directory!\n");
      break;
    }
    
    if (!(entry[11] ^ (unsigned char)0x08))
    {
      printf("VOLID\n");
      continue;
    }
    if (!(entry[11] ^ (unsigned char)0xF)) 
    {
      //printf("LONG NAME!\n");
      char* entry_name = read_name_long_entry(entry);
      if (!long_name) 
      {
        long_name = entry_name;
      }
      else 
      {
        char* temp = long_name;
        long_name = calloc(1, strlen(temp) + strlen(entry_name) + 1);
        strcpy(long_name, entry_name); strcat(long_name, temp);
      }
    } 
    else 
    {
      //printf("SHORT NAME!\n");
      char* short_name = read_short_entry(entry);
      if (long_name) 
      {
        printf("%s\n", long_name);
        free(long_name);
        long_name = NULL;
      }
      else 
      {
        printf("%s\n", short_name);
      }
      if ((entry[11] & (unsigned char)0x10) && entry[0] ^ (unsigned char)0x2E)  
      {
        printf("Is dir!\n");
        uint32_t cluster_hi1 = ((uint32_t) entry[20]) << 16;
        uint32_t cluster_hi2 = ((uint32_t) entry[21]) << 24;
        uint32_t cluster_lo1 = ((uint32_t) entry[26]);
        uint32_t cluster_lo2 = (uint32_t) entry[27] << 8;
        uint32_t new_dir_cluster_num = 
          cluster_hi1 | cluster_hi2 | cluster_lo1 | cluster_lo2;
        printf("dir_clus_num %" PRIu32 "\n", new_dir_cluster_num);
        char* name;
        if (long_name) 
        {
          name = long_name;
        }
        else
        {
          name = short_name;
        }
        read_dir_cluster(name, disk, new_dir_cluster_num, fs, serializef);
        lseek64(disk, (off64_t) (cluster_addr + offset), SEEK_SET);
      }
    }
    //print_hex_memory(entry, 32);

    if (offset == 512 * volID->sectors_per_cluster) 
    {
      //printf("offset: %d bytes_cluster: %d\n", offset, 512 * volID->sectors_per_cluster);
      uint32_t fat_entry = get_fat_entry(disk, cluster_num, fs);
      if (fat_entry == 0x0FFFFFFF) 
      {
        printf("End of Directory! (fat_entry) \n");
        return;
      }
      cluster_num = fat_entry;
      printf("fat_entry %" PRIu32 "\n", fat_entry);
      cluster_addr = get_cluster_addr(fs,fat_entry);
      printf("cluster_addr %" PRId64 "\n", cluster_addr);
      offset = 0;
      lseek64(disk, (off64_t) (cluster_addr), SEEK_SET);
    }
  }
  free(entry);
}

int fat32_serialize(int disk, struct fs* fs, int serializef)
{
  read_dir_cluster("", disk, 2, fs, serializef);
  return 0;
}

int fat32_cleanup(struct fs* fs)
{ 
  return 0;
}

