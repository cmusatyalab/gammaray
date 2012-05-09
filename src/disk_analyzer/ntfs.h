#ifndef XRAY_DISK_ANALYZER_NTFS_H
#define XRAY_DISK_ANALYZER_NTFS_H

#include <stdint.h>
#include <stdio.h>

#define SECTOR_SIZE 512
#define NTFS_MFT_OFFSET 8192

struct ntfs_superblock
{
    uint64_t test;
} __attribute__((packed));

struct ntfs_boot_file
{
    uint8_t jump[3];
    int8_t sys_id[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;    
    uint8_t unused[7];
    uint8_t media;
    uint16_t unused2;
    uint16_t sectors_per_track;
    uint16_t number_of_heads;
    uint8_t unused3[8];
    uint32_t signature;
    uint64_t sectors_in_volume;
    uint64_t lcn_mft;
    uint64_t lcn_mftmirr;
    uint32_t clusters_per_mft;
    uint32_t volume_serial;
} __attribute__((packed));

struct ntfs_standard_attribute_header
{
    uint32_t attribute_type;
    uint32_t length;
    uint8_t non_resident_flag;
    uint8_t name_length;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t attribute_id;
    uint32_t length_of_attribute;
    uint16_t offset_of_attribute;
    uint8_t indexed_flag;
    uint8_t padding;
} __attribute__((packed));

struct ntfs_standard_information
{
    uint64_t c_time;
    uint64_t a_time;
    uint64_t m_time;
    uint64_t r_time;
    uint32_t dos_permissions;
    uint32_t max_num_versions;
    uint32_t version_num;
    uint32_t class_id;
    uint32_t owner_id;
    uint32_t security_id;
    uint64_t quota_charged;
    uint64_t update_squence_num;
} __attribute__((packed));

struct ntfs_file_name
{
    uint64_t parent_ref;
    uint64_t c_time;
    uint64_t a_time;
    uint64_t m_time;
    uint64_t r_time;
    uint64_t allocated_size;
    uint64_t real_size;
    uint32_t flags;
    uint32_t something;
    uint8_t name_len;
} __attribute__((packed));

struct ntfs_file_record
{
    uint32_t magic; /* ASCII FILE or BAAD */
    uint16_t offset_update_seq;
    uint16_t size_usn;
    uint64_t lsn;
    uint16_t seq_num;
    uint16_t hard_link_count;
    uint16_t offset_first_attribute;
    uint16_t flags;
    uint32_t real_size;
    uint32_t allocated_size;
    uint64_t file_ref_base;
    uint16_t next_attr_id;
    uint16_t align;
    uint32_t rec_num;
} __attribute__((packed));

int ntfs_probe(FILE* disk, int64_t partition_offset,
               struct ntfs_boot_file* bootf);
int ntfs_print_file_record(struct ntfs_file_record * record);
uint64_t ntfs_lcn_to_offset(struct ntfs_boot_file* bootf,
                            int64_t partition_offset, uint64_t lcn);
int ntfs_walk_mft(FILE* disk, struct ntfs_boot_file* bootf,
                  int64_t partition_offset);
#endif
