#ifndef XRAY_DISK_ANALYZER_NTFS_H
#define XRAY_DISK_ANALYZER_NTFS_H

#include <stdint.h>
#include <stdio.h>

struct ntfs_superblock
{
    uint64_t test;
} __attribute__((packed));

struct standard_attribute_header
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

struct standard_information
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

struct file_record
{
    uint32_t magic; /* ASCII FILE or BAAD */
    uint16_t offset_update_seq;
    uint16_t size_usn;
    uint64_t lsn;
    uint16_t seq_num;
    uint16_t hard_link_count;
    uint16_t offset_first_attribute;
    uint16_t flags;
} __attribute__((packed));

int ntfs_probe(FILE* disk, int64_t partition_offset,
               struct ntfs_superblock* superblock);

#endif
