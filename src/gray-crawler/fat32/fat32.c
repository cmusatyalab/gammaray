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

void print_hex_memory(void *mem, int n) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<n;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}


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
  
  fprintf_light_white(stdout, "pt_off: 0x%.16"PRIx64".\n", fs->pt_off);

  lseek64(disk, (off64_t) (fs->pt_off + 0x0B), SEEK_SET);
  if (read(disk, (void*)&volumeID->bytes_per_sector, sizeof(uint16_t)) != 
          sizeof(uint16_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 bytes_per_sector.\n");
        return -1;
  }

  lseek64(disk, (off64_t) (fs->pt_off + 0x0D), SEEK_SET);
  if (read(disk, (void*)&volumeID->sectors_per_cluster, sizeof(uint8_t)) != 
          sizeof(uint8_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 sectors_per_cluster.\n");
        return -1;
  }

  printf("SectorsPerCluster %" PRIu8 "\n",volumeID->sectors_per_cluster);
  lseek64(disk, (off64_t) (fs->pt_off + 0x0E), SEEK_SET);
  if (read(disk, (void*)&volumeID->num_reserved_sectors, sizeof(uint16_t)) != 
          sizeof(uint16_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 num_reserved_sectors.\n");
        return -1;
  }

  printf("NumReservedSectors %" PRIu16 "\n",volumeID->num_reserved_sectors);

  lseek64(disk, (off64_t) (fs->pt_off + 0x10), SEEK_SET);
  if (read(disk, (void*)&volumeID->num_fats, sizeof(uint8_t)) != 
          sizeof(uint8_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 num_fats.\n");
        return -1;
  }
  fprintf_light_white(stdout, "fat32 numfats: %x\n", volumeID->num_fats);
  lseek64(disk, (off64_t) (fs->pt_off + 0x24), SEEK_SET);
  if (read(disk, (void*)&volumeID->sectors_per_fat, sizeof(uint32_t)) != 
          sizeof(uint32_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 sectors_per_fat.\n");
        return -1;
  }

  printf("SectorsPerFat %" PRIu32 "\n",volumeID->sectors_per_fat);
  lseek64(disk, (off64_t) (fs->pt_off + 0x2C), SEEK_SET);
  if (read(disk, (void*)&volumeID->root_dir_first_cluster, sizeof(uint32_t)) != 
          sizeof(uint32_t))
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 root_dir_first_cluster.\n");
        return -1;
  }
  printf("RootDirFstCluster%" PRIu32 "\n",volumeID->root_dir_first_cluster);

  char *volLab = calloc(1, 12);
  lseek64(disk, (off64_t) (fs->pt_off + 71), SEEK_SET);
  if (read(disk, (void*)volLab, 11) != 11)
  {
    fprintf_light_red(stderr, "Error while trying to read fat32 signatureeee.\n");
        return -1;
  }
  print_hex_memory(volLab, 11);

  lseek64(disk, (off64_t) (fs->pt_off + 0x1FE), SEEK_SET);
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
  lseek64(disk, (off64_t) (fat_entry_addr), SEEK_SET);
  uint32_t result;
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

void print_file_info(struct fat32_file* file_info) {
  printf("name: %s\n", file_info->name);
  printf("path: %s\n", file_info->path);
  printf("is_dir: %s\n", file_info->is_dir ? "true" : "false");
  printf("cluster_num: %d\n", file_info->cluster_num);
}

void free_file_info(struct fat32_file* file_info) {
  free(file_info->name);
  free(file_info->path);
}

char* make_path_name(char* path, char* name) {
  char* file_path = calloc(1, strlen(path) + strlen(name) + 2);
  strcpy(file_path, path); 
  strcpy(file_path + strlen(path), "/");
  strcpy(file_path + strlen(path) + 1, name);
  return file_path;
}
void read_dir_cluster(char* path, int disk, uint32_t cluster_num, struct fs* fs, int serializef) 
{
  int64_t cluster_addr = get_cluster_addr(fs, cluster_num); int offset = 0;
  unsigned char* entry = calloc(1, 32); 
  lseek64(disk, (off64_t) (cluster_addr), SEEK_SET);
  struct fat32_volumeID* volID = fs->fs_info;
  char* long_name = NULL;
  struct fat32_file file_info;
  while (true) 
  {
    if (read(disk, (void*)entry, 32) != 32)
    {
      fprintf_light_red(stderr, "Error while trying to read record.\n");
        return;
    }
    offset += 32;
    
    if (!(entry[0] ^ (unsigned char)0xe5))
    {
      // This entry is empty.
      continue;
    }
    if (!entry[0]) 
    {
      // No more directory entries.
      break;
    }
    
    if (!(entry[11] ^ (unsigned char)0x08))
    {
      // This entry is the volume id.
      continue;
    }
    if (!(entry[11] ^ (unsigned char)0xF)) 
    {
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
      char* short_name = read_short_entry(entry);
      if (long_name) 
      {
        file_info.name = long_name;
        long_name = NULL;
      }
      else 
      {
        file_info.name = short_name;
      }
      
      uint32_t cluster_hi1 = ((uint32_t) entry[20]) << 16;
      uint32_t cluster_hi2 = ((uint32_t) entry[21]) << 24;
      uint32_t cluster_lo1 = ((uint32_t) entry[26]);
      uint32_t cluster_lo2 = (uint32_t) entry[27] << 8;
      uint32_t file_cluster_num = 
          cluster_hi1 | cluster_hi2 | cluster_lo1 | cluster_lo2;
      file_info.cluster_num = file_cluster_num;
      file_info.path = make_path_name(path, file_info.name);
      if ((entry[11] & (unsigned char)0x10) && entry[0] ^ (unsigned char)0x2E)  
      {
        file_info.is_dir = true;
        read_dir_cluster(file_info.path, disk, file_cluster_num, fs, serializef);
        lseek64(disk, (off64_t) (cluster_addr + offset), SEEK_SET);
      }
      else
      {
        file_info.is_dir = false;
      }
      print_file_info(&file_info);
      free_file_info(&file_info);
    }

    if (offset == 512 * volID->sectors_per_cluster) 
    {
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

