#ifndef XRAY_DISK_ANALYZER_NTFS_H
#define XRAY_DISK_ANALYZER_NTFS_H

#include <stdint.h>
#include <stdio.h>

#define SECTOR_SIZE 512

#define UPPER_NIBBLE(u) ((u & 0x0f0) >> 4) 
#define LOWER_NIBBLE(u) ((u & 0x0f))

/* partition start, for probing and bootstrapping */
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
    int32_t clusters_per_mft_record;
    int32_t clusters_per_index_record;
    uint32_t volume_serial;
} __attribute__((packed));

/* MFT parsing; full FILE RECORD header */
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
    uint16_t usn_num;
} __attribute__((packed));

struct ntfs_full_file_record
{
    struct ntfs_file_record header;
    uint64_t len;
    uint8_t* data;
};

/* MFT Parsing; full attribute header */
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

struct ntfs_non_resident_header
{
    uint64_t last_vcn;
    uint16_t data_run_offset;
    uint16_t compression_size;
    uint32_t padding;
    uint64_t allocated_size;
    uint64_t real_size;
    uint64_t initialized_size;
} __attribute__((packed));

/* -- special attributes -- */
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
    uint32_t reparse;
    uint8_t name_len;
    uint8_t fnamespace;
} __attribute__((packed));

struct ntfs_data_run_header
{
    uint8_t packed_sizes;
} __attribute__((packed));

struct ntfs_update_sequence
{
    uint16_t usn_num;
    uint16_t usn_size;
    uint8_t* data;
} __attribute__((packed));

struct ntfs_file_reference
{
    uint8_t record_number[6];
    uint16_t seq_num;
} __attribute__((packed));

struct ntfs_index_root
{
    uint32_t attribute_type;
    uint32_t collation_rule;
    uint32_t index_alloc_entry_size;
    uint8_t clusters_per_index_record;
    uint8_t padding[3];
} __attribute__((packed));

struct ntfs_index_header
{
    uint32_t first_entry_offset;
    uint32_t total_size;
    uint32_t allocated_size;
    uint32_t flags;
} __attribute__((packed));

struct ntfs_index_entry
{
    struct ntfs_file_reference ref;
    uint16_t length;
    uint16_t stream_length;
    uint16_t flags;
} __attribute__((packed));

uint64_t ntfs_file_record_size (struct ntfs_boot_file* bootf);
int ntfs_probe(FILE* disk, int64_t partition_offset,
               struct ntfs_boot_file* bootf);
int ntfs_print_boot_file(struct ntfs_boot_file* bootf,
                         int64_t partition_offset);
int ntfs_walk_mft(FILE* disk, struct ntfs_boot_file* bootf,
                  int64_t partition_offset);
int ntfs_diff_file_records(FILE* disk, uint64_t recorda, uint64_t recordb,
                           int64_t partition_offset,
                           struct ntfs_boot_file* bootf);
int ntfs_read_file_record(FILE* disk, uint64_t record_num,
                          int64_t partition_offset, 
                          struct ntfs_boot_file* bootf,
                          uint8_t* buf);
int ntfs_diff_file_record_buffs(uint8_t* recorda, uint8_t* recordb,
                                int64_t partition_offset,
                                struct ntfs_boot_file* bootf);
#endif
