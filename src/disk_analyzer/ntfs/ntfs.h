#ifndef XRAY_DISK_ANALYZER_NTFS_H
#define XRAY_DISK_ANALYZER_NTFS_H

#include <stdint.h>
#include <stdio.h>
#include "bson.h"

#define SECTOR_SIZE 512

#define UPPER_NIBBLE(u) ((u & 0x0f0) >> 4) 
#define LOWER_NIBBLE(u) ((u & 0x0f))

enum NTFS_ATTRIBUTE_TYPE
{
    NTFS_STANDARD_INFORMATION    =   0x10,
    NTFS_ATTRIBUTE_LIST          =   0x20,
    NTFS_FILE_NAME               =   0x30,
    NTFS_VOLUME_VERSION          =   0x40,
    NTFS_OBJECT_ID               =   0x40,
    NTFS_SECURITY_DESCRIPTOR     =   0x50,
    NTFS_VOLUME_NAME             =   0x60,
    NTFS_VOLUME_INFORMATION      =   0x70,
    NTFS_DATA                    =   0x80,
    NTFS_INDEX_ROOT              =   0x90,
    NTFS_INDEX_ALLOCATION        =   0xA0,
    NTFS_BITMAP                  =   0xB0,
    NTFS_SYMBOLIC_LINK           =   0xC0,
    NTFS_REPARSE_POINT           =   0xC0,
    NTFS_EA_INFORMATION          =   0xD0,
    NTFS_EA                      =   0xE0,
    NTFS_PROPERTY_SET            =   0xF0,
    NTFS_LOGGED_UTILITY_STREAM   =   0x100
};

enum NTFS_FILE_FLAGS
{
    NTFS_F_READ_ONLY               = 0x0001,
    NTFS_F_HIDDEN                  = 0x0002,
    NTFS_F_SYSTEM                  = 0x0004,
    NTFS_F_ARCHIVE                 = 0x0020,
    NTFS_F_DEVICE                  = 0x0040,
    NTFS_F_NORMAL                  = 0x0080,
    NTFS_F_TEMPORARY               = 0x0100,
    NTFS_F_SPARSE_FILE             = 0x0200,
    NTFS_F_REPARSE_POINT           = 0x0400,
    NTFS_F_COMPRESSED              = 0x0800,
    NTFS_F_OFFLINE                 = 0x1000,
    NTFS_F_NOT_CONTENT_INDEXED     = 0x2000,
    NTFS_F_ENCRYPTED               = 0x4000,
    NTFS_F_DIRECTORY               = 0x10000000,
    NTFS_F_INDEX_VIEW              = 0x20000000
};

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

struct ntfs_index_record_header
{
    uint8_t magic[4];
    uint16_t update_seq_offset;
    uint16_t size_usn; /* in words */
    uint64_t log_seq_num;
    uint64_t index_vcn;
    uint32_t offset_to_index_entries; /* - 0x18 */
    uint32_t size_of_index_entries;
    uint32_t allocated_size_of_index_entries;
    uint8_t is_leaf;
    uint8_t padding[3];
    uint16_t usn_num;
} __attribute__((packed));

struct ntfs_index_record_entry
{
    struct ntfs_file_reference ref;
    uint16_t size;
    uint16_t file_name_offset;
    uint16_t flags;
    uint16_t padding;
    struct ntfs_file_reference parent;
    uint64_t c_time;
    uint64_t m_time;
    uint64_t a_time;
    uint64_t r_time;
    uint64_t file_allocated_size;
    uint64_t file_real_size;
    uint32_t file_flags;
    uint32_t ea_reparse;
    uint8_t filename_length;
    uint8_t filename_namespace;
    /* then filename, padding, VCN if not leaf */
} __attribute__((packed));

uint64_t ntfs_file_record_size(struct ntfs_boot_file* bootf);
uint64_t ntfs_cluster_size(struct ntfs_boot_file* bootf);
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
                          uint8_t* buf, struct bson_info* bson);
int ntfs_diff_file_record_buffs(uint8_t* recorda, uint8_t* recordb,
                                int64_t partition_offset,
                                struct ntfs_boot_file* bootf);
int ntfs_get_attribute(uint8_t* record, void* attr, uint64_t* offset,
                       enum NTFS_ATTRIBUTE_TYPE type);
int ntfs_get_size(uint8_t* data, struct ntfs_standard_attribute_header* sah,
                  uint64_t* offset, uint64_t* fsize);
int ntfs_serialize_fs(struct ntfs_boot_file* bootf, int64_t partition_offset,
                      uint32_t pte_num, char* mount_point, FILE* serializedf);
int ntfs_serialize_fs_tree(FILE* disk, struct ntfs_boot_file* bootf,
                           int64_t partition_offset, char* mount_point,
                           FILE* serializedf);
int ntfs_serialize_file_record(FILE* disk, struct ntfs_boot_file* bootf,
                               int64_t partition_offset, char* prefix,
                               FILE* serializedf, uint8_t* data,
                               struct bson_info* bson);
int ntfs_read_index_record_entry(uint8_t* data, uint64_t* offset,
                                 struct ntfs_index_record_entry* ire);
uint64_t ntfs_get_reference_int(struct ntfs_file_reference* ref);
int ntfs_utf16_to_char(char* utf16_fname, size_t inlen, char* char_fname,
                       size_t outlen);
#endif
