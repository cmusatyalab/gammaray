#include "color.h"
#include "ntfs.h"
#include "util.h"
#include "bson.h"

#include <assert.h>
#include <errno.h>
#include <iconv.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define NRH_DIFF(element) \
    if (nrha->element != nrhb->element) \
        fprintf_light_red(stdout, "%s diff.\n", #element); \
    else \
        fprintf_yellow(stdout, "%s match.\n", #element);

#define REC_DIFF(element) \
    if (reca->element != recb->element) \
        fprintf_light_red(stdout, "%s diff.\n", #element); \
    else \
        fprintf_yellow(stdout, "%s match.\n", #element);

#define SAH_DIFF(element) \
    if (saha->element != sahb->element) \
        fprintf_light_red(stdout, "%s diff.\n", #element); \
    else \
        fprintf_yellow(stdout, "%s match.\n", #element);



char* namespaces[] = { "POSIX",
                       "Win32",
                       "DOS",
                       "Win32&DOS"
                     };  

wchar_t* ignore_files[] = { L"$MFT",
                            L"$MFTMirr",
                            L"$LogFile",
                            L"$Volume",
                            L"$AttrDef",
                            L"$Bitmap",
                            L"$Boot",
                            L"$BadClus",
                            L"$Quota",
                            L"$Secure",
                            L"$UpCase",
                            L"$Extend",
                            L"$ObjId",
                            L"$Reparse",
                            L"$UsnJrnl",
                            L"$Repair",
                            L"$Tops",
                            L"$Config",
                            L"$Delete",
                            L"$ObjId",
                            L"$Quota",
                            L"$Repair.log",
                            L"$RmMetadata",
                            L"$Txf",
                            L"$TxfLog.blf",
                            L"$TXFLO~1",
                            L"$TXFLO~2",
                            L"$TxfLogContainer00000000000000000001",
                            L"$TxfLogContainer00000000000000000002",
                            NULL 
                          };




/* helpers */
bool ntfs_ignore_file(wchar_t* fname)
{
    int i = 0;
    while (ignore_files[i])
    {
        if (wcscmp(ignore_files[i++], fname) == 0)
            return true;
    }
    return false;
}

char* ntfs_namespace(uint8_t namespace)
{
    if (namespace > 3)
        return "unknown";

    return namespaces[namespace]; 
}

uint64_t ntfs_lcn_to_offset(struct ntfs_boot_file* bootf, int64_t partition_offset,
                            uint64_t lcn)
{
    uint64_t bytes_per_cluster = bootf->bytes_per_sector *
                                 bootf->sectors_per_cluster;
    return (lcn*bytes_per_cluster) + partition_offset;
}

uint64_t ntfs_lcn_len(struct ntfs_boot_file* bootf,
                      uint64_t count)
{
    uint64_t bytes_per_cluster = bootf->bytes_per_sector *
                                 bootf->sectors_per_cluster;
    return count*bytes_per_cluster;
}


/* printers for all structs */
int ntfs_print_boot_file(struct ntfs_boot_file* bootf, int64_t partition_offset)
{
    fprintf_light_blue(stdout, "-- Analyzing Boot File $Boot --\n");
    fprintf_yellow(stdout, "boot->sys_id: %4s\n", bootf->sys_id);
    fprintf_yellow(stdout, "boot->bytes_per_sector: %"PRIu16"\n",
                           bootf->bytes_per_sector);
    fprintf_yellow(stdout, "boot->sectors_per_cluster: %"PRIu8"\n",
                           bootf->sectors_per_cluster);
    fprintf_light_yellow(stdout, "boot->media: 0x%"PRIx8"\n", bootf->media);
    fprintf_yellow(stdout, "boot->sectors_per_track: %"PRIu16"\n", bootf->sectors_per_track);
    fprintf_yellow(stdout, "boot->number_of_heads: %"PRIu16"\n", bootf->number_of_heads);
    fprintf_yellow(stdout, "boot->signature: 0x%"PRIx32"\n", bootf->signature);
    fprintf_yellow(stdout, "boot->sectors_in_volume: %"PRIu64"\n", bootf->sectors_in_volume);
    fprintf_light_yellow(stdout, "boot->lcn_mft: %"PRIu64"\n", bootf->lcn_mft);
    fprintf_green(stdout, "\tlcn_mft offset: %"PRIu64"\n", ntfs_lcn_to_offset(bootf, partition_offset, bootf->lcn_mft));
    fprintf_light_yellow(stdout, "boot->lcn_mftmirr: %"PRIu64"\n", bootf->lcn_mftmirr);
    fprintf_green(stdout, "\tlcn_mft offset: %"PRIu64"\n", ntfs_lcn_to_offset(bootf, partition_offset, bootf->lcn_mftmirr));
    fprintf_yellow(stdout, "boot->clusters_per_mft_record: %"PRId32"\n", bootf->clusters_per_mft_record);
    fprintf_yellow(stdout, "boot->clusters_per_index_record: %"PRId32"\n", bootf->clusters_per_index_record);
    fprintf_yellow(stdout, "boot->volume_serial: %"PRIu32"\n", bootf->volume_serial);
    
    return EXIT_SUCCESS;
}

int ntfs_print_file_record(struct ntfs_file_record* rec)
{
    uint8_t* magic = (uint8_t*) &(rec->magic);
    fprintf_light_blue(stdout, "file_record.magic: %.4s\n", magic);
    fprintf_yellow(stdout, "file_record.offset_update_seq: %0.4"PRIx16"\n", rec->offset_update_seq);
    fprintf_light_yellow(stdout, "file_record.size_usn: %"PRIu16"\n", rec->size_usn);
    fprintf_yellow(stdout, "file_record.lsn: %"PRIu64"\n", rec->lsn);
    fprintf_yellow(stdout, "file_record.seq_num: %"PRIu16"\n", rec->seq_num);
    fprintf_yellow(stdout, "file_record.hard_link_count: %"PRIu16"\n", rec->hard_link_count);
    fprintf_yellow(stdout, "file_record.offset_first_attributes: %0.4"PRIx16"\n", rec->offset_first_attribute);
    fprintf_yellow(stdout, "file_record.flags: %"PRIx16"\n", rec->flags);
    fprintf_yellow(stdout, "file_record.real_size: %"PRIu16"\n", rec->real_size);
    fprintf_yellow(stdout, "file_record.allocated_size: %"PRIu16"\n", rec->allocated_size);
    fprintf_yellow(stdout, "file_record.file_ref_base: %"PRIu16"\n", rec->file_ref_base);
    fprintf_yellow(stdout, "file_record.next_attr_id: %"PRIu16"\n", rec->next_attr_id);
    fprintf_yellow(stdout, "file_record.rec_num: %"PRIu32"\n", rec->rec_num);
    fprintf_light_yellow(stdout, "file_record.usn_num: %"PRIu16"\n", rec->usn_num);
    return EXIT_SUCCESS;
}

int ntfs_print_index_record_header(struct ntfs_index_record_header* irh)
{
    fprintf_light_blue(stdout, "irh->magic: %.4s\n", irh->magic);
    fprintf_yellow(stdout, "irh->update_seq_offset: %"PRIu16"\n", irh->update_seq_offset);
    fprintf_yellow(stdout, "irh->size_update_seq: %"PRIu16"\n", irh->size_usn); /* in words */
    fprintf_yellow(stdout, "irh->log_seq_num: %"PRIu64"\n", irh->log_seq_num);
    fprintf_yellow(stdout, "irh->index_vcn: %"PRIu64"\n", irh->index_vcn);
    fprintf_yellow(stdout, "irh->offset_to_index_entries: %"PRIu32"\n", irh->offset_to_index_entries); /* - 0x18 */
    fprintf_yellow(stdout, "irh->size_of_index_entries: %"PRIu32"\n", irh->size_of_index_entries);
    fprintf_yellow(stdout, "irh->allocated_size_of_index_entries: %"PRIu32"\n", irh->allocated_size_of_index_entries);
    fprintf_yellow(stdout, "irh->is_leaf: 0x%"PRIx8"\n", irh->is_leaf);
    fprintf_yellow(stdout, "irh->usn: [0x%"PRIx16"]\n", irh->usn_num);
    return EXIT_SUCCESS;
}


int ntfs_print_index_record_entry(struct ntfs_index_record_entry* ire)
{
    uint64_t ref;

    memcpy(&ref, ire->ref.record_number, 6);
    fprintf_light_blue(stdout, "ire->ref: %"PRIu64"\n", ref);
    fprintf_yellow(stdout, "ire->size: %"PRIu16"\n", ire->size);
    fprintf_yellow(stdout, "ire->file_name_offset: %"PRIu16"\n", ire->file_name_offset);
    fprintf_yellow(stdout, "ire->flags: %"PRIu16"\n", ire->flags);
    fprintf_yellow(stdout, "ire->c_time: %"PRIu64"\n", ire->c_time);
    fprintf_yellow(stdout, "ire->m_time: %"PRIu64"\n", ire->m_time);
    fprintf_yellow(stdout, "ire->a_time: %"PRIu64"\n", ire->a_time);
    fprintf_yellow(stdout, "ire->file_allocated_size: %"PRIu64"\n", ire->file_allocated_size);
    fprintf_yellow(stdout, "ire->file_real_size: %"PRIu64"\n", ire->file_real_size);
    fprintf_yellow(stdout, "ire->file_flags: 0x%"PRIx64"\n", ire->file_flags);
    fprintf_yellow(stdout, "ire->filename_length: %"PRIu8"\n", ire->filename_length);
    fprintf_yellow(stdout, "ire->filename_namespace: %"PRIu8"\n", ire->filename_namespace);
    return EXIT_SUCCESS;
}

int ntfs_print_standard_attribute_header(struct ntfs_standard_attribute_header* sah)
{
    fprintf_yellow(stdout, "sah.attribute_type: 0x%"PRIx32"\n", sah->attribute_type);
    fprintf_yellow(stdout, "sah.length: %"PRIu32"\n", sah->length);
    fprintf_yellow(stdout, "sah.non_resident_flag: 0x%"PRIx8"\n", sah->non_resident_flag);
    fprintf_yellow(stdout, "sah.name_length: %"PRIu8"\n", sah->name_length);
    fprintf_yellow(stdout, "sah.name_offset: %"PRIu16"\n", sah->name_offset);
    fprintf_yellow(stdout, "sah.flags: 0x%"PRIx16"\n", sah->flags);
    fprintf_yellow(stdout, "sah.attribute_id: %"PRIu16"\n", sah->attribute_id);
    fprintf_yellow(stdout, "sah.length_of_attribute: %"PRIu32"\n", sah->length_of_attribute);
    fprintf_yellow(stdout, "sah.offset_of_attribute: %"PRIu16"\n", sah->offset_of_attribute);
    fprintf_yellow(stdout, "sah.indexed_flag: 0x%"PRIx8"\n", sah->indexed_flag);
    return EXIT_SUCCESS;
}

int ntfs_print_non_resident_header(struct ntfs_non_resident_header* header)
{
    fprintf_yellow(stdout, "non_resident.last_vcn: %"PRIu64"\n", header->last_vcn);
    fprintf_yellow(stdout, "non_resident.data_run_offset: %"PRIu16"\n", header->data_run_offset);
    fprintf_yellow(stdout, "non_resident.compression_size: %"PRIu16"\n", header->compression_size);
    fprintf_yellow(stdout, "non_resident.allocated_size: %"PRIu64"\n", header->allocated_size);
    fprintf_yellow(stdout, "non_resident.real_size: %"PRIu64"\n", header->real_size);
    fprintf_yellow(stdout, "non_resident.initialized_size: %"PRIu64"\n", header->initialized_size);
    return EXIT_SUCCESS;
}

int ntfs_print_standard_information(struct ntfs_standard_information* si)
{
    fprintf_yellow(stdout, "c_time: %"PRIu64"\n", si->c_time);
    fprintf_yellow(stdout, "a_time: %"PRIu64"\n", si->a_time);
    fprintf_yellow(stdout, "m_time: %"PRIu64"\n", si->m_time);
    fprintf_yellow(stdout, "r_time: %"PRIu64"\n", si->r_time);
    fprintf_yellow(stdout, "Class ID: %"PRIu32"\n", si->class_id);
    fprintf_yellow(stdout, "Owner ID: %"PRIu32"\n", si->owner_id);
    fprintf_yellow(stdout, "Security ID: %"PRIu32"\n", si->security_id);
    fprintf_yellow(stdout, "Permissions: %"PRIo32"\n", si->dos_permissions);
    return EXIT_SUCCESS;
}

int ntfs_print_file_name(struct ntfs_file_name* rec)
{
    fprintf_yellow(stdout, "rec->c_time: %"PRIu64"\n", rec->c_time);
    fprintf_yellow(stdout, "rec->a_time: %"PRIu64"\n", rec->a_time);
    fprintf_yellow(stdout, "rec->m_time: %"PRIu64"\n", rec->m_time);
    fprintf_yellow(stdout, "rec->r_time: %"PRIu64"\n", rec->r_time);
    fprintf_yellow(stdout, "rec->allocated_size: %"PRIu64"\n", rec->allocated_size);
    fprintf_yellow(stdout, "rec->real_size: %"PRIu64"\n", rec->real_size);
    fprintf_yellow(stdout, "rec->flags: %"PRIx32"\n", rec->flags);
    fprintf_yellow(stdout, "rec->name_len: %"PRIu8"\n", rec->name_len);
    return EXIT_SUCCESS;
}

int ntfs_print_data_run_header(struct ntfs_data_run_header* header)
{
    fprintf_light_yellow(stdout, "data_run.raw: %x\n", header->packed_sizes);
    fprintf_yellow(stdout, "data_run.offset_size: %u\n", UPPER_NIBBLE(header->packed_sizes));
    fprintf_yellow(stdout, "data_run.length_size: %u\n", LOWER_NIBBLE(header->packed_sizes));
    return EXIT_SUCCESS;
}


int ntfs_print_update_sequence(struct ntfs_update_sequence* seq)
{
    int i;
    fprintf_yellow(stdout, "seq.usn_num: %0.4"PRIx16"\n", seq->usn_num);
    fprintf_yellow(stdout, "seq.usn_size: %"PRIu16"\n", seq->usn_size);
    fprintf_yellow(stdout, "seq.data: ");
    for (i = 0; i < seq->usn_size; i++)
    {
        fprintf_light_yellow(stdout, " %0.2"PRIx8" ", seq->data[i]);
    }
    fprintf(stdout, "\n");
    return EXIT_SUCCESS;
}

int ntfs_print_index_root(struct ntfs_index_root* root)
{
    fprintf_yellow(stdout, "root.attribute_type: 0x%"PRIx32"\n",
                                                   root->attribute_type);
    fprintf_yellow(stdout, "root.collation_rule: %"PRIu32"\n",
                                                   root->collation_rule);
    fprintf_yellow(stdout, "root.index_alloc_entry_size: %"PRIu32"\n",
                                                 root->index_alloc_entry_size);
    fprintf_yellow(stdout, "root.clusters_per_index_record: %"PRIu8"\n",
                                              root->clusters_per_index_record);
    return EXIT_SUCCESS;
}

int ntfs_print_index_header(struct ntfs_index_header* hdr)
{
    fprintf_yellow(stdout, "hdr.first_entry_offset: %"PRIu32"\n",
                                                   hdr->first_entry_offset);
    fprintf_yellow(stdout, "hdr.total_size: %"PRIu32"\n",
                                                   hdr->total_size);
    fprintf_yellow(stdout, "hdr.allocated_size: %"PRIu32"\n",
                                                   hdr->allocated_size);
    fprintf_yellow(stdout, "hdr.flags: %"PRIu8"\n",
                                                   hdr->flags);
    return EXIT_SUCCESS;
}

int ntfs_print_index_entry(struct ntfs_index_entry* entry, uint8_t* data)
{
    uint64_t ref;

    memcpy(&ref, entry->ref.record_number, 6);
    //ref = ref >> 16;
    hexdump((uint8_t*)&(entry->ref.record_number), 6);
    fprintf_yellow(stdout, "entry.file_reference: 0x%"PRIx64"\n",
                                                   ref);
    fprintf_yellow(stdout, "entry.length: %"PRIu16"\n",
                                                   entry->length);
    fprintf_yellow(stdout, "entry.stream_length: %"PRIu16"\n",
                                                   entry->stream_length);
    fprintf_yellow(stdout, "entry.flags: %"PRIu16"\n",
                                                   entry->flags);
    if (entry->flags & 0x1)
        fprintf_yellow(stdout, "entry.vcn: %"PRIu64"\n", *((uint64_t*) &(data[entry->length - 8])));
    return EXIT_SUCCESS;
}

/* read boot record/probe for valid NTFS partition */
int ntfs_probe(FILE* disk, int64_t partition_offset,
               struct ntfs_boot_file* bootf)
{
    uint32_t bits;
    uint8_t* bytes;

    if (fseeko(disk, partition_offset, SEEK_SET))
    {
        fprintf_light_red(stderr, "Error seeking to partition offset "
                                  "position while NTFS probing.\n");
        return EXIT_FAILURE;
    }

    if (fread(bootf, 1, sizeof(*bootf), disk) != sizeof(*bootf))
    {
        fprintf_light_red(stderr, "Error reading BOOT record.\n");
        return EXIT_FAILURE;
    }

    if (strncmp((char*) bootf->sys_id, "NTFS", 4) != 0)
    {
        fprintf_light_red(stderr, "NTFS probe failed.\n");
        return EXIT_FAILURE;
    }

    bytes = (uint8_t*) &bootf->clusters_per_mft_record;
    if (top_bit_set(bytes[0]))
    {
        bits = highest_set_bit(bootf->clusters_per_mft_record);
        bootf->clusters_per_mft_record = sign_extend(bootf->clusters_per_mft_record, bits);
    }


    bytes = (uint8_t*) &bootf->clusters_per_index_record;
    if (top_bit_set(bytes[0]))
    {
        bits = highest_set_bit(bootf->clusters_per_index_record);
        bootf->clusters_per_index_record = sign_extend(bootf->clusters_per_index_record, bits);
    }

    return EXIT_SUCCESS;
}


uint64_t ntfs_file_record_size(struct ntfs_boot_file* bootf)
{
    return bootf->clusters_per_mft_record > 0 ?
           bootf->clusters_per_mft_record *
           bootf->sectors_per_cluster *
           bootf->bytes_per_sector :
           2 << -1 * (bootf->clusters_per_mft_record + 1);
}


/* read FILE record */
int ntfs_read_file_record(FILE* disk, uint64_t record_num,
                          int64_t partition_offset, 
                          struct ntfs_boot_file* bootf,
                          struct bitarray* bits,
                          uint8_t* buf, struct bson_info* bson)
{
    uint64_t record_size = ntfs_file_record_size(bootf); 
    int64_t offset = ntfs_lcn_to_offset(bootf, partition_offset,
                                        bootf->lcn_mft) +
                     record_num * record_size;
    int64_t sector = offset / 512;
    int32_t inode_num = record_num;
    struct bson_kv val;

    val.type = BSON_STRING;
    val.size = strlen("file");
    val.key = "type";
    val.data = "file";

    bson_serialize(bson, &val);
    
    val.type = BSON_INT64;
    val.key = "inode_sector";
    val.data = &sector;

    bson_serialize(bson, &val);

    sector = offset % (bootf->bytes_per_sector * bootf->sectors_per_cluster);
    val.type = BSON_INT64;
    val.key = "inode_offset";
    val.data = &sector;

    bson_serialize(bson, &val);

    val.type = BSON_INT32;
    val.key = "inode_num";
    val.data = &inode_num;

    bson_serialize(bson, &val);

    if (buf == NULL)
    {
        fprintf_light_red(stderr, "Error malloc()ing to read file record.\n");
        return 0;
    }

    if (fseeko(disk, offset, SEEK_SET))
    {
        fprintf_light_red(stderr, "Error seeking to FILE record.\n");
        return 0;
    }

    if (fread(buf, 1, record_size, disk) != record_size)
    {
        fprintf_light_red(stderr, "Error reading FILE record data.\n");
        return 0;
    }

    if (strncmp((char*) buf, "FILE", 4) != 0)
    {
        fprintf_light_cyan(stderr, "FILE magic bytes mismatch.\n");
        return 0;
    }

    return record_size;
}


/* read FILE record header */
int ntfs_read_file_record_header(uint8_t* data, uint64_t* offset,
                                 struct ntfs_file_record* rec)
{
    memcpy(rec, &(data[*offset]), sizeof(*rec));
    *offset += sizeof(*rec);
    return EXIT_SUCCESS;
}


/* read update sequence array */
int ntfs_read_update_sequence(uint8_t* data, uint64_t* offset,
                              uint16_t size_usn, uint16_t usn_num,
                              struct ntfs_update_sequence* seq)
{
    uint8_t* buf = malloc(2*(size_usn) - 2);
    memcpy(buf, &(data[*offset]), 2*(size_usn) - 2);
    *offset += 2*(size_usn) - 2;

    seq->usn_num = usn_num;
    seq->usn_size = 2*(size_usn) - 2;
    seq->data = buf;

    return EXIT_SUCCESS;
}

/* apply fixups */
int ntfs_fixup_data(uint8_t* data, uint64_t data_len,
                    struct ntfs_update_sequence* seq)
{
    uint64_t data_counter = 510;
    uint64_t seq_counter = 0;

    ntfs_print_update_sequence(seq);
    for(; data_counter < data_len; data_counter += 512)
    {
        if (seq_counter < seq->usn_size)
        {
            if (*((uint16_t*) &(data[data_counter])) != seq->usn_num)
            {
                fprintf_light_red(stderr, "Corrupt sector encountered by "
                                          "fixup.\n");
                fprintf_light_red(stderr, "Saw: %0.4"PRIx16"\n",
                                          *((uint16_t*) &(data[data_counter])));
                return EXIT_FAILURE;
            }

            data[data_counter] = seq->data[seq_counter];
            data[data_counter + 1] = seq->data[seq_counter + 1]; 
            seq_counter += 2;
        }
        else
        {
            break;
        }
    }

    return EXIT_SUCCESS;
}

/* read attribute */
int ntfs_read_attribute_header(uint8_t* data, uint64_t* offset,
                               struct ntfs_standard_attribute_header* sah)
{
    memcpy(sah, &(data[*offset]), sizeof(*sah));
    *offset += sizeof(*sah);

    return EXIT_SUCCESS; 
}

/* read attribute */
int ntfs_read_non_resident_attribute_header(uint8_t* data, uint64_t* offset,
                                            struct ntfs_non_resident_header* nrh)
{
    memcpy(nrh, &(data[*offset]), sizeof(*nrh));
    *offset += sizeof(*nrh);

    return EXIT_SUCCESS; 
}

int ntfs_read_attribute_data(uint8_t* data, uint64_t* offset,
                             uint8_t* buf, uint64_t buf_len,
                             struct ntfs_standard_attribute_header* sah)
{
    *offset += sah->offset_of_attribute - sizeof(*sah);

    if (sah->length_of_attribute > buf_len)
    {
        fprintf_light_red(stderr, "Resident attribute over %"PRIu64" bytes.\n",
                                  buf_len);
        return EXIT_FAILURE;
    }

    memcpy(buf, &(data[*offset]), sah->length_of_attribute);
    *offset += sah->length_of_attribute;
    return EXIT_SUCCESS;
}

FILE* ntfs_create_reconstructed_file(char* name, bool extension,
                                     bool reconstruct)
{
    FILE* reconstructed = NULL;
    char fname[1024] = { 0 };
    char* mode = extension ? "a" : "wx";

    if (name)
    {
        strcat(fname, "/tmp/win7/");
        strcat(fname, name);

        fprintf_light_green(stdout, "Dynamic path: %s\n", fname);

        /* create "versions" of files depending on number of valid file records */
        /* TODO: could loop forever */
        while ((reconstructed = fopen(fname, mode)) == NULL)
        {
            strcat(fname, "0");
        }
    }

    if (extension && name)
        fprintf_light_red(stderr, "Opened '%s' in 'a' mode.\n", fname);

    return reconstructed;
}

/* handler for resident */
int ntfs_handle_resident_data_attribute(uint8_t* data, uint64_t* offset,
                                        uint8_t* buf, uint64_t buf_len,
                                        char* name,
                                        struct ntfs_standard_attribute_header* sah,
                                        bool extension,
                                        bool dir,
                                        struct bson_info* bson,
                                        bool save_sectors)
{
    FILE* reconstructed = NULL;
    struct bson_kv value, value1;
    struct bson_info* sectors = bson_init();
    char count[11];
    int32_t value1data = -1;
    
    fprintf_yellow(stdout, "\tData is resident.\n");
    fprintf_white(stdout, "\tsah->offset_of_attribute: %x\tsizeof(sah) %x\n", sah->offset_of_attribute, sizeof(*sah));
    fprintf_green(stdout, "\tSeeking to %d\n", sah->offset_of_attribute - sizeof(*sah));

    ntfs_read_attribute_data(data, offset, buf, buf_len, sah);
  
    if (save_sectors)
    {
        value.type = BSON_ARRAY;
        value.key = "sectors";

        value1.type = BSON_INT32;
        value1.key = count;
        snprintf(count, 11, "%"PRIu32, 0);
        value1.data = &value1data;

        bson_serialize(sectors, &value1);
        bson_finalize(sectors);
        value.data = sectors;
        bson_serialize(bson, &value);
        bson_cleanup(sectors);
    }

    if (reconstructed)
    {
        reconstructed = ntfs_create_reconstructed_file(name, extension, dir);
        if (fwrite(buf, 1, sah->length_of_attribute, reconstructed) != sah->length_of_attribute)
        {
            fclose(reconstructed);
            fprintf_light_red(stderr, "Error writing resident attribute.\n");
            return EXIT_FAILURE;
        }

        fclose(reconstructed);
    }

    return EXIT_SUCCESS;
}

int ntfs_parse_data_run(uint8_t* data, uint64_t* offset,
                        uint64_t* length, int64_t* lcn)
{
    struct ntfs_data_run_header drh; 
    uint8_t len_size = 0;
    uint8_t offset_size = 0;

    memcpy(&drh, &(data[*offset]), sizeof(drh));
    *offset += 1;

    ntfs_print_data_run_header(&drh);

    if (drh.packed_sizes)
    {
        offset_size = UPPER_NIBBLE(drh.packed_sizes);
        len_size = LOWER_NIBBLE(drh.packed_sizes);

        memcpy(((uint8_t*) length), &(data[*offset]), len_size);
        *offset += len_size;

        memcpy(((uint8_t*) lcn), &(data[*offset]), offset_size);
        *offset += offset_size;

        if (top_bit_set(((uint8_t *) lcn)[offset_size-1]))
            *lcn = sign_extend64(*lcn, highest_set_bit64(*lcn));
        
        return 1;
    }
    
    return 0;
}

uint64_t ntfs_cluster_size(struct ntfs_boot_file *bootf)
{
    return bootf->bytes_per_sector * bootf->sectors_per_cluster;
}

/* handler for non-resident */
int ntfs_handle_non_resident_data_attribute(uint8_t* data, uint64_t* offset,
                                            char* name,
                                            struct ntfs_standard_attribute_header* sah,
                                            struct ntfs_boot_file* bootf,
                                            struct bitarray* bits,
                                            int64_t partition_offset,
                                            FILE* disk,
                                            bool extension,
                                            uint8_t** stream,
                                            bool reconstruct,
                                            struct bson_info* bson,
                                            bool save_sectors,
                                            uint64_t* stream_len) 
{
    FILE* reconstructed = NULL;
    uint8_t buf[4096];
    uint64_t real_size = 0;
    int64_t run_lcn = 0;
    int64_t run_lcn_bytes = 0;
    int64_t prev_lcn = 0;
    uint64_t run_length = 0;
    uint64_t run_length_bytes = 0;
    uint64_t stream_position = 0;
    struct ntfs_non_resident_header nrh;
    struct bson_kv value, value1;
    struct bson_info* sectors = bson_init();
    char count[11];
    int32_t value1data = -1, sector_counter = 0;
    uint64_t i;

    int counter = 0;

    if (save_sectors)
    {
        value.type = BSON_ARRAY;
        value.key = "sectors";
        value.data = sectors;

        value1.type = BSON_INT32;
        value1.key = count;
        value1.data = &value1data;
        fprintf_light_blue(stdout, "SAVING SECTOR INIT.\n");
    }

    ntfs_read_non_resident_attribute_header(data, offset, &nrh);
    ntfs_print_non_resident_header(&nrh);

    real_size = nrh.real_size;
    if (stream)
    {
        *stream = malloc(real_size);
        *stream_len = real_size;
    }

    fprintf_yellow(stdout, "\tData is non-resident\n");
    fprintf_white(stdout, "\tnrh->offset_of_attribute: %x\tsizeof(nrh+sah) %x\n", nrh.data_run_offset, sizeof(nrh) + sizeof(*sah));
    fprintf_green(stdout, "\tSeeking to %d\n", nrh.data_run_offset - sizeof(*sah) - sizeof(nrh));

    *offset += nrh.data_run_offset - sizeof(*sah) - sizeof(nrh);
    while (ntfs_parse_data_run(data, offset, &run_length, &run_lcn) && real_size)
    {
        fprintf_light_blue(stdout, "got a sequence %d\n", counter++);
        run_length_bytes = run_length * bootf->bytes_per_sector * bootf->sectors_per_cluster;
        fprintf_light_red(stdout, "prev_lcn: %"PRIx64"\n", prev_lcn);
        fprintf_light_red(stdout, "run_lcn: %"PRIx64" (%"PRId64")\n",
                                  run_lcn, run_lcn);
        fprintf_light_red(stdout, "prev_lcn + run_lcn: %"PRIx64"\n",
                                   prev_lcn + run_lcn);
        run_lcn_bytes = ntfs_lcn_to_offset(bootf, partition_offset,
                                           prev_lcn + run_lcn);
        fprintf_light_blue(stdout, "run_lcn_bytes: %"PRIx64
                                   " run_length_bytes: %"PRIx64"\n",
                                   run_lcn_bytes,
                                   run_length_bytes);

        assert(prev_lcn + run_lcn >= 0);
        assert(prev_lcn + run_lcn < 26214400);

        if (save_sectors)
        {
            for (i = 0; i < run_length_bytes / 512; i += 8)
            {
                snprintf(count, 11, "%"PRIu32, sector_counter++);
                value1data = run_lcn_bytes / 512 + i;
                bson_serialize(sectors, &value1);
            }
        }

        if (stream && fseeko(disk, run_lcn_bytes, SEEK_SET))
        {
            fprintf_light_red(stderr, "Error seeking to data run LCN offset: %"
                                       PRIu64"\n", run_lcn_bytes);
            exit(1);
        }

        while (run_length_bytes)
        {
            run_length_bytes = run_length_bytes > real_size ? real_size : run_length_bytes;
            if (run_length_bytes >= 4096)
            {
                if (stream && fread(buf, 4096, 1, disk) != 1)
                {
                    fprintf_light_red(stderr, "Error reading run data.\n");
                    exit(1);
                    return EXIT_FAILURE;
                }

                if (reconstructed && fwrite(buf, 4096, 1, reconstructed) != 1)
                {
                    fprintf_light_red(stderr, "Error writing run data.\n");
                    exit(1);
                    return EXIT_FAILURE;
                }

                if (stream)
                {
                    memcpy(&((*stream)[stream_position]), buf, 4096);
                    stream_position += 4096;
                }

                run_length_bytes -= 4096;
                real_size -= 4096;
            }
            else
            {
                if (stream && fread(buf, run_length_bytes, 1, disk) != 1)
                {
                    fprintf_light_red(stderr, "Error reading run data.\n");
                    exit(1);
                    return EXIT_FAILURE;
                }

                if (reconstructed && fwrite(buf, run_length_bytes, 1, reconstructed) != 1)
                {
                    fprintf_light_red(stderr, "Error writing run data.\n");
                    exit(1);
                    return EXIT_FAILURE;
                }

                if (stream)
                {
                    memcpy(&((*stream)[stream_position]), buf,
                           run_length_bytes);
                    stream_position += 4096;
                }

                real_size -= run_length_bytes;
                run_length_bytes -= run_length_bytes;
            }
        }

        prev_lcn = prev_lcn + run_lcn;
        run_length = 0;
        run_length_bytes = 0;
        run_lcn = 0;
        run_lcn_bytes = 0;
    }

    if (save_sectors)
    {
        bson_finalize(sectors);
        bson_serialize(bson, &value);
        bson_cleanup(sectors);
    }

    if (reconstructed)
        fclose(reconstructed);

    return EXIT_SUCCESS;
}

int ntfs_utf16_to_char(char* utf16_fname, size_t inlen, char* char_fname,
                       size_t outlen)
{
    iconv_t cd = iconv_open("US-ASCII", "UTF-16");
    char* utf16_fnamep = utf16_fname;
    char** utf16_fnamepp = &utf16_fnamep;
    char* char_fnamep = char_fname;
    char** char_fnamepp = &char_fnamep;
    
    if (cd < 0)
    {
        fprintf_light_red(stderr, "Error creating conversion struct.\n");
        return -1;
    } 

    if (iconv(cd, utf16_fnamepp, &inlen, char_fnamepp, &outlen) == (size_t) -1)
    {
        fprintf_light_red(stderr, "bytes: %x %x %x %x %x %x %x %x\n",
                                  utf16_fname[0],
                                  utf16_fname[1],
                                  utf16_fname[2],
                                  utf16_fname[3],
                                  utf16_fname[4],
                                  utf16_fname[5],
                                  utf16_fname[6],
                                  utf16_fname[7]
                                  );

        fprintf_light_red(stderr, "Error converting to wchar_t.\n");

        switch (errno)
        {
            case E2BIG:
                fprintf_light_red(stderr, "There is not sufficient room at"
                                          " *outbuf\n");
                break;
            case EILSEQ:
                fprintf_light_red(stderr, "An invalid multibyte sequence "
                                          "has been encountered in the "
                                          "input.\n");
                break;
            case EINVAL:
                fprintf_light_red(stderr, "An incomplete multibyte "
                                          "sequence has been encountered "
                                          "in the input.\n");
                break;
            default:
                fprintf_light_red(stderr, "An unknown iconv error was "
                                          "encountered.\n");
        };

        return -1;
    }

    iconv_close(cd);

    return EXIT_SUCCESS;
}

int ntfs_utf16_to_wchar(char* utf16_fname, size_t inlen, char* wchar_fname,
                        size_t outlen)
{
    iconv_t cd = iconv_open("WCHAR_T", "UTF-16");
    char* utf16_fnamep = utf16_fname;
    char** utf16_fnamepp = &utf16_fnamep;
    char* wchar_fnamep = wchar_fname;
    char** wchar_fnamepp = &wchar_fnamep;
    
    if (cd < 0)
    {
        fprintf_light_red(stderr, "Error creating conversion struct.\n");
        return -1;
    } 

    if (iconv(cd, utf16_fnamepp, &inlen, wchar_fnamepp, &outlen) == (size_t) -1)
    {
        fprintf_light_red(stderr, "bytes: %x %x %x %x %x %x %x %x\n",
                                  utf16_fname[0],
                                  utf16_fname[1],
                                  utf16_fname[2],
                                  utf16_fname[3],
                                  utf16_fname[4],
                                  utf16_fname[5],
                                  utf16_fname[6],
                                  utf16_fname[7]
                                  );

        fprintf_light_red(stderr, "Error converting to wchar_t.\n");

        switch (errno)
        {
            case E2BIG:
                fprintf_light_red(stderr, "There is not sufficient room at"
                                          " *outbuf\n");
                break;
            case EILSEQ:
                fprintf_light_red(stderr, "An invalid multibyte sequence "
                                          "has been encountered in the "
                                          "input.\n");
                break;
            case EINVAL:
                fprintf_light_red(stderr, "An incomplete multibyte "
                                          "sequence has been encountered "
                                          "in the input.\n");
                break;
            default:
                fprintf_light_red(stderr, "An unknown iconv error was "
                                          "encountered.\n");
        };

        return -1;
    }

    iconv_close(cd);

    return EXIT_SUCCESS;
}

/* dispatch handler for file name */
int ntfs_dispatch_file_name_attribute(uint8_t* data, uint64_t* offset,
                                      char** name,
                                      struct ntfs_standard_attribute_header* sah)
{
    struct ntfs_file_name fname;
    char* file_name = malloc(512);
    char* file_namep = file_name;
    char** file_namepp = &file_namep;
    char file_name_encoded[512];
    char* file_name_encodedp = file_name_encoded;
    char** file_name_encodedpp = &file_name_encodedp;
    iconv_t cd = iconv_open("US-ASCII", "UTF-16");
    size_t outbytes = 512;
    size_t inbytes; 

    memset(file_name, 0, 512);
    memset(file_name_encoded, 0, 512);
    
    if (cd < 0)
    {
        fprintf_light_red(stderr, "Error creating conversion struct.\n");
        return -1;
    } 

    if (sah->attribute_type == 0x30) /* file name */
    {
        /* TODO: refactor */
        *offset += sah->offset_of_attribute - sizeof(*sah);
        fname = *((struct ntfs_file_name*) &(data[*offset]));
        *offset += sizeof(struct ntfs_file_name);

        //ntfs_print_file_name(&fname);

        memcpy(file_name_encoded, &(data[*offset]), 2*fname.name_len);
        *offset += 2*fname.name_len;

        file_name_encodedp = file_name_encoded;
        file_name_encodedpp = &file_name_encodedp;
        inbytes = 2*fname.name_len;

        hexdump((uint8_t*)*file_name_encodedpp, 24);
        if (iconv(cd, (char**) file_name_encodedpp, &inbytes, (char**) file_namepp, &outbytes) == (size_t) -1)
        {
            fprintf_light_red(stderr, "bytes: %x %x %x %x %x %x %x %x\n",
                                      file_name_encodedp[0],
                                      file_name_encodedp[1],
                                      file_name_encodedp[2],
                                      file_name_encodedp[3],
                                      file_name_encodedp[4],
                                      file_name_encodedp[5],
                                      file_name_encodedp[6],
                                      file_name_encodedp[7]
                                      );

            fprintf_light_red(stderr, "Error converting to wchar_t.\n");
            switch (errno)
            {
                case E2BIG:
                    fprintf_light_red(stderr, "There is not sufficient room at"
                                              " *outbuf\n");
                    break;
                case EILSEQ:
                    fprintf_light_red(stderr, "An invalid multibyte sequence "
                                              "has been encountered in the "
                                              "input.\n");
                    break;
                case EINVAL:
                    fprintf_light_red(stderr, "An incomplete multibyte "
                                              "sequence has been encountered "
                                              "in the input.\n");
                    break;
                default:
                    fprintf_light_red(stderr, "An unknown iconv error was "
                                              "encountered.\n");
            };

            return -1;
        }
        else
        {
            if (*name)
                free(*name);
            *name = file_name;
        }
    }

    fprintf(stdout, "inbytes = %zu outbytes = %zu\n", inbytes, outbytes);
    iconv_close(cd);

    return EXIT_SUCCESS;
}

int ntfs_read_index_entry(struct ntfs_index_entry* entry, uint8_t* data,
                          uint64_t* offset)
{
    memcpy(entry, &(data[*offset]), sizeof(*entry));
    if (entry->length == 0)
        return EXIT_FAILURE;
    return 0;
}

int ntfs_read_index_entries(uint8_t* data, uint64_t* offset)
{
    struct ntfs_index_entry entry;

    while (!ntfs_read_index_entry(&entry, data, offset))
    {
        ntfs_print_index_entry(&entry, &(data[*offset]));
        *offset += entry.length;
        if (entry.flags & 0x02)
            break;
    }

    return 0;
}

/* good */
int ntfs_read_index_header(uint8_t* data, uint64_t* offset,
                           char* name,
                           struct ntfs_standard_attribute_header* sah,
                           struct ntfs_boot_file* bootf,
                           int64_t partition_offset,
                           FILE* disk,
                           struct bson_info* bson, FILE* serializedf)
{
    struct ntfs_index_header hdr;

    memcpy(&hdr, &(data[*offset]), sizeof(hdr));

    ntfs_print_index_header(&hdr);

    *offset += hdr.first_entry_offset;

    return 0;
}

int ntfs_dispatch_index_root_attribute(uint8_t* data, uint64_t* offset,
                                       char* name,
                                       struct ntfs_standard_attribute_header* sah,
                                       struct ntfs_boot_file* bootf,
                                       struct bitarray* bits,
                                       int64_t partition_offset,
                                       FILE* disk,
                                       struct bson_info* bson, FILE* serializedf)
{
    struct ntfs_index_root root;

    if (sah->attribute_type != 0x90)
    {
        fprintf_light_red(stderr, "Index Root handler, bad attribute!\n");
        return EXIT_FAILURE;
    }

    *offset += sah->offset_of_attribute - sizeof(*sah);
    root = *((struct ntfs_index_root*) &(data[*offset]));
    ntfs_print_index_root(&root);

    *offset += sizeof(root);

    ntfs_read_index_header(data, offset, name, sah, bootf, partition_offset,
                           disk, bson, serializedf);
    /* good */

    ntfs_read_index_entries(data, offset);
    return 0;
}

int ntfs_dispatch_standard_information_attribute(uint8_t* data,
                                    uint64_t* offset,
                                    char* fname,
                                    struct ntfs_standard_attribute_header* sah)
{
    struct ntfs_standard_information nsi;
    *offset += sah->offset_of_attribute - sizeof(*sah);
    nsi = *((struct ntfs_standard_information*) &(data[*offset]));

    ntfs_print_standard_information(&nsi);

    return 0;
}

int ntfs_get_size(uint8_t* data, struct ntfs_standard_attribute_header* sah,
                  uint64_t* data_offset, uint64_t* fsize)
{
    struct ntfs_non_resident_header nrh;

    if (sah->non_resident_flag)
    {
        ntfs_read_non_resident_attribute_header(data, data_offset, &nrh);
        *fsize = nrh.real_size; 
    }
    else
    {
        *fsize = sah->length_of_attribute;
    }

    return EXIT_SUCCESS;
}

/* dispatch handler for data */
int ntfs_dispatch_data_attribute(uint8_t* data, uint64_t* offset,
                                 char* name,
                                 struct ntfs_standard_attribute_header* sah,
                                 struct ntfs_boot_file* bootf,
                                 struct bitarray* bits,
                                 int64_t partition_offset,
                                 FILE* disk,
                                 bool extension,
                                 uint8_t** stream,
                                 bool reconstruct,
                                 struct bson_info* bson,
                                 bool save_sectors,
                                 uint64_t* stream_len)
{
    uint8_t resident_buffer[4096];

    if (sah->attribute_type != 0x80 &&
        sah->attribute_type != 0xA0)
    {
        fprintf_light_red(stderr, "Data handler, not a data attribute.\n");
        return EXIT_FAILURE;
    }
    
    if ((sah->flags & 0x0001) != 0x0000) /* check compressed */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for compressed files"
                                  " yet.\n");
        return EXIT_FAILURE;
    }

    if ((sah->flags & 0x4000) != 0x0000) /* check encrypted */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for encrypted files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    if ((sah->flags & 0x8000) != 0x0000) /* check sparse */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for sparse files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    if (sah->non_resident_flag)
    {
        fprintf_light_red(stdout, "fname to non-resident data handler: %s\n", name);
        ntfs_handle_non_resident_data_attribute(data, offset, name, sah, bootf, bits,
                                                partition_offset, disk,
                                                extension, stream, reconstruct, bson, save_sectors, stream_len);
    }
    else
    {
        fprintf_light_red(stdout, "fname to resident data handler: %s\n", name);
        ntfs_handle_resident_data_attribute(data, offset, resident_buffer, 4096,
                                            name, sah, extension, reconstruct, bson, save_sectors);
        if (stream)
        {
            *stream = malloc(4096);
            *stream_len = 4096;
            memcpy(stream, resident_buffer, 4096);
        }
    }

    return EXIT_SUCCESS;
}

int ntfs_read_index_record_entry(uint8_t* data, uint64_t* offset,
                                 struct ntfs_index_record_entry* ire)
{
    *ire = *((struct ntfs_index_record_entry*) &(data[*offset]));
    *offset += sizeof(struct ntfs_index_record_entry);

    return EXIT_SUCCESS;
}

uint64_t ntfs_get_reference_int(struct ntfs_file_reference* ref)
{
    uint64_t ret = 0;
    memcpy(&ret, ref->record_number, 6);
    return ret;
}

int ntfs_dispatch_index_allocation_attribute(uint8_t* data, uint64_t* offset,
                                 char* prefix,
                                 struct ntfs_standard_attribute_header* sah,
                                 struct ntfs_boot_file* bootf,
                                 struct bitarray* bits,
                                 int64_t partition_offset,
                                 FILE* disk,
                                 struct bson_info* bson,
                                 FILE* serializedf)
{
    uint8_t* stream, *ostream, file_record[ntfs_file_record_size(bootf)];
    uint64_t stream_offset = 0;
    struct ntfs_index_record_header irh;
    struct ntfs_update_sequence seq;
    struct ntfs_index_record_entry ire;
    char* utf16_fname;
    size_t utf16_fname_size;
    size_t current_fname_size = 512;
    char* current_fname = malloc(current_fname_size);
    char name[32767];
    struct bson_info* datas, *bson2;
    struct bson_kv data_value, data_array;
    struct bson_info* sectors;
    struct bson_kv sector_value, sector_array;
    static uint32_t sector = 0;
    char count[11];
    uint64_t stream_len = 0;
    uint64_t counter = 0;

    sectors = bson_init();
    sector_array.type = BSON_ARRAY;
    sector_array.key = "sectors";

    datas = bson_init();
    data_array.type = BSON_ARRAY;
    data_array.key = "data";

    snprintf(count, 11, "%"PRIu32, sector);
    data_value.key = count;
    data_value.type = BSON_BINARY;

    sector_value.key = count;
    sector_value.type = BSON_INT32;
    sector_value.data = &sector;

    /* read index records off disk */
    if (ntfs_dispatch_data_attribute(data, offset, name, sah, bootf, bits,
                                   partition_offset, disk, false, &stream,
                                   false, bson, false, &stream_len))
        return EXIT_FAILURE;

    ostream = stream;

    while (stream_offset < stream_len)
    {
        fprintf_light_blue(stdout, "INDX Parsing stream_offset == %"PRIu64" and stream_len == %"PRIu64"\n",
                stream_offset, stream_len);

        data_value.data = stream;
        ////hexdump(stream, 4096);

        irh = *((struct ntfs_index_record_header*) stream);
        stream_offset += sizeof(irh);

        if ((irh.magic[0] != 'I') || 
            (irh.magic[1] != 'N') ||
            (irh.magic[2] != 'D') ||
            (irh.magic[3] != 'X'))
            break; /* TODO: why do these appear? */

        ntfs_print_index_record_header(&irh);
        ntfs_read_update_sequence(stream, &stream_offset,
                                  irh.size_usn, irh.usn_num,
                                  &seq);
        if (ntfs_fixup_data(stream, irh.allocated_size_of_index_entries + 0x18, &seq))
            break; /* TODO: why does this ever fail? */

        ire.flags = 0;
        stream_offset = irh.offset_to_index_entries + 0x18;
        
        data_value.size = 0x18 + irh.allocated_size_of_index_entries;

        snprintf(count, 11, "%"PRIu32, sector);
        bson_serialize(datas, &data_value);
        bson_serialize(sectors, &sector_value);
        sector++;

        /* walk all entries */
        while (!(ire.flags & 0x02))
        {
            assert(counter++ < 30000);
            /* read index entries */
            ntfs_read_index_record_entry(stream, &stream_offset, &ire);
            ntfs_print_index_record_entry(&ire);

            if (ntfs_get_reference_int(&(ire.ref)) < 15 ||
                ntfs_get_reference_int(&(ire.parent)) == ntfs_get_reference_int(&(ire.ref)))
            {
                stream_offset += ire.size - sizeof(struct ntfs_index_record_entry);
                continue;
            }

            utf16_fname = (char*) &(stream[stream_offset]);
            utf16_fname_size = ire.filename_length * 2;
            memset(current_fname, 0, current_fname_size);
            ntfs_utf16_to_char(utf16_fname, utf16_fname_size,
                               (char*) current_fname, current_fname_size);

            fprintf_light_green(stdout, "Current fname: %s\n", current_fname);
            memset(name, 0, 32767);
            strncpy(name, prefix, strlen(prefix));
            strcat(name, current_fname);

            stream_offset += ire.size - sizeof(struct ntfs_index_record_entry);

            if (ire.flags & 0x01)
                fprintf_light_yellow(stdout, "Has sub-node!\n");

            if (ire.flags & 0x02)
                fprintf_light_yellow(stdout, "Is last entry; without file!\n");

            if (ire.file_flags & NTFS_F_READ_ONLY)
                fprintf_light_green(stdout, "NTFS_F_READONLY\n");
            if (ire.file_flags & NTFS_F_HIDDEN)
                fprintf_light_green(stdout, "NTFS_F_HIDDEN\n");
            if (ire.file_flags & NTFS_F_SYSTEM)
                fprintf_light_green(stdout, "NTFS_F_SYSTEM\n");
            if (ire.file_flags & NTFS_F_DIRECTORY)
            {
                fprintf_light_green(stdout, "NTFS_F_DIRECTORY\n");
                strcat(name, "/");
            }

            if (ntfs_get_reference_int(&(ire.ref)))
            {
                bson2 = bson_init();
                if (ntfs_read_file_record(disk,
                                          ntfs_get_reference_int(&(ire.ref)),
                                          partition_offset, bootf, bits,
                                          file_record, bson2) == 0)
                {
                    fprintf_light_red(stderr, "Failed reading file record %"
                                           PRIu64"\n",
                                           ntfs_get_reference_int(&(ire.ref)));
                    return EXIT_FAILURE;
                }           

                ntfs_serialize_file_record(disk, bootf, bits, partition_offset,
                                           name, serializedf, file_record,
                                           bson2);
            }

        }
        stream_offset += 4096 - stream_offset;
        stream += stream_offset;
    }

    bson_finalize(sectors);
    sector_array.data = sectors;
    bson_serialize(bson, &sector_array);
    bson_cleanup(sectors);

    bson_finalize(datas);
    data_array.data = datas;
    bson_serialize(bson, &data_array);
    bson_cleanup(datas);

    bson_finalize(bson);
    bson_writef(bson, serializedf);
    bson_cleanup(bson);

    /* cleanup */
    if (seq.data)
        free(seq.data);

    free(ostream);

    return EXIT_SUCCESS;
}

/* attribute dispatcher */
int ntfs_attribute_dispatcher(uint8_t* data, uint64_t* offset, char** fname,
                              struct ntfs_standard_attribute_header* sah,
                              struct ntfs_boot_file* bootf,
                              int64_t partition_offset,
                              FILE* disk,
                              bool extension)
{
    int ret = 1;
    uint64_t old_offset = *offset;
    
    if (*fname)
        fprintf(stdout, "%s\n", *fname);

    if (sah->attribute_type == 0x30)
    {
        fprintf_light_yellow(stdout, "Dispatching file name attribute.\n");
           ret = -1;
        fprintf(stdout, "dispatched file name: %s\n", *fname);
    }
    else if (sah->attribute_type == 0x80 && *fname)
    {
        fprintf_light_yellow(stdout, "Dispatching data attribute.\n");
        fprintf(stdout, "with fname: %s\n", *fname);
        //if (ntfs_dispatch_data_attribute(data, offset, *fname, sah, bootf,
        //                                 partition_offset, disk,
        //                                 extension, NULL, true, NULL, false))
        //    ret = -1;
    }
    else if (sah->attribute_type == 0x90 && *fname)
    {
        fprintf_light_yellow(stdout, "Dispatching index root attribute.\n");
        /* TODO: fix this function */
        //if (ntfs_dispatch_index_root_attribute(data, offset, *fname, sah,
        //                                       bootf, partition_offset, disk,
        //                                       extension))
        //    ret = -1;
    }
    else if (sah->attribute_type == 0xA0 && *fname)
    {
        fprintf_light_yellow(stdout, "Dispatching index allocation "
                                     "attribute.\n");
        //if (ntfs_dispatch_index_allocation_attribute(data, offset, *fname, sah,
        //                                         bootf, partition_offset, disk,
        //                                         extension))
        //    ret = -1;
    }
    else if (sah->attribute_type == 0x10)
    {
        fprintf_light_yellow(stdout, "Dispatching standard information "
                                     "attribute.\n");
        if (ntfs_dispatch_standard_information_attribute(data, offset, *fname,
                                                         sah))
            ret = -1;
    }
    else
    {
        fprintf_light_yellow(stdout, "Dispatching unhandled attribute.\n");
    }

    *offset = old_offset + sah->length - sizeof(*sah);

    if (*((int32_t*) &(data[*offset])) == -1)
        ret = 0;

    fprintf_light_red(stdout, "returning %d\n", ret);
    return ret;
}

int ntfs_get_attribute(uint8_t* data, void* attr, uint64_t* offset,
                       enum NTFS_ATTRIBUTE_TYPE type)
{
    struct ntfs_file_record rec;
    struct ntfs_standard_attribute_header sah;

    ntfs_read_file_record_header(data, offset, &rec);

    if (strncmp("FILE", (const char*) &rec.magic, (size_t) 4) != 0)
        return EXIT_FAILURE;

    *offset = rec.offset_first_attribute;

    while (ntfs_read_attribute_header(data, offset, &sah) == 0)
    {
        if (sah.attribute_type == type)
        {
            switch (type)
            {
                case NTFS_FILE_NAME:
                    memcpy(attr,
                       &(data[*offset + sah.offset_of_attribute - sizeof(sah)]),
                       sizeof(struct ntfs_file_name)); 
                    return EXIT_SUCCESS;
                case NTFS_INDEX_ALLOCATION:
                case NTFS_INDEX_ROOT:
                case NTFS_DATA:
                    memcpy(attr,
                       &(sah),
                       sizeof(struct ntfs_standard_attribute_header)); 
                    return EXIT_SUCCESS;
                default:
                    fprintf_light_red(stdout, "Unknown attribute to get.\n");
                    return EXIT_FAILURE;
            };
        }

        *offset += sah.length - sizeof(sah);
        
        if (*((int32_t*) &(data[*offset])) == -1)
        {
            fprintf_light_yellow(stdout, "Reached end of attributes while searching.\n");
            break;
        }
    }

    fprintf_light_red(stdout, "Failed to find attribute.\n");
    return EXIT_FAILURE;
}


/* meta-walk MFT */
int ntfs_walk_mft(FILE* disk, struct ntfs_boot_file* bootf, struct bitarray* bits,
                  int64_t partition_offset)
{
    struct ntfs_file_record rec;
    struct ntfs_update_sequence seq;
    struct ntfs_standard_attribute_header sah;
    uint8_t* data = malloc(ntfs_file_record_size(bootf));
    int64_t file_record_offset;
    uint64_t data_offset = 0;
    char* fname = NULL;
    int counter = 0;
    uint64_t file_record_counter = 0;
    bool extension = false;

    file_record_offset =
        ntfs_lcn_to_offset(bootf, partition_offset, bootf->lcn_mft); 

    fprintf_light_red(stdout, "Current %"PRIu64" file_record_offset: %"
                              PRId64"\n",
                              file_record_counter,
                              file_record_offset);
    while (ntfs_read_file_record(disk, file_record_counter, partition_offset, bootf, bits, data, NULL) &&
           file_record_counter <= 5)
    {
        extension = false;
        data_offset = 0;
        fprintf_light_red(stdout, "Current %"PRIu64" file_record_offset: %"
                                  PRId64"\n",
                                  file_record_counter++,
                                  file_record_offset);
        file_record_offset += ntfs_file_record_size(bootf);
        ntfs_read_file_record_header(data, &data_offset, &rec);
        ntfs_print_file_record(&rec);
        ntfs_read_update_sequence(data, &data_offset, rec.size_usn,
                                  rec.usn_num, &seq);
        ntfs_fixup_data(data, 1024, &seq);

        /* check if valid record we want to check */
        if (!(rec.flags & 0x01)) /* in use */
           continue;
        if (rec.flags & 0x02) /* not a dir */
        {
            fprintf_light_red(stdout, "DIRECTORY ENCOUNTERED.\n");
        }
        if (rec.file_ref_base) /* BASE FILE Record */
        {
            fprintf_light_red(stderr, "Uh oh: Extension FILE Record "
                                      "encountered.\n");
            extension = true;
        }
        
        data_offset = rec.offset_first_attribute;
        counter = 0;
        while (ntfs_read_attribute_header(data, &data_offset, &sah) == 0 &&
               counter < 1024)
        {
            ntfs_print_standard_attribute_header(&sah);

            if (ntfs_attribute_dispatcher(data, &data_offset, &fname, &sah,
                                          bootf, partition_offset, disk,
                                          extension) == 0)
                break;
            counter++;
        }

        if (seq.data)
        {
            free(seq.data);
            seq.data = NULL;
        }
        
        if (fname)
        {
            free(fname);
            fname = NULL;
        }
    }
    
    return EXIT_SUCCESS;
}


int __diff_file_records(struct ntfs_file_record* reca,
                        struct ntfs_file_record* recb)
{
    fprintf_light_cyan(stdout, "\n-- Diff'ing File Record Headers --\n");
    REC_DIFF(magic)
    REC_DIFF(offset_update_seq)
    REC_DIFF(size_usn)
    REC_DIFF(lsn)
    REC_DIFF(seq_num)
    REC_DIFF(hard_link_count);
    REC_DIFF(offset_first_attribute);
    REC_DIFF(flags);
    REC_DIFF(real_size);
    REC_DIFF(allocated_size);
    REC_DIFF(file_ref_base);
    REC_DIFF(next_attr_id);
    REC_DIFF(align);
    REC_DIFF(rec_num);
    REC_DIFF(usn_num);
    fprintf_light_cyan(stdout, "-- Finished diff'ing File Record Headers --\n");
    return EXIT_SUCCESS;
}

int __diff_non_resident_headers(struct ntfs_non_resident_header* nrha,
                                struct ntfs_non_resident_header* nrhb)
{
    fprintf_light_cyan(stdout, "\n-- Diff'ing NRH --\n");
    NRH_DIFF(last_vcn);
    NRH_DIFF(data_run_offset);
    NRH_DIFF(compression_size);
    NRH_DIFF(padding);
    NRH_DIFF(allocated_size);
    NRH_DIFF(real_size);
    NRH_DIFF(initialized_size);
    fprintf_light_cyan(stdout, "-- Finished diff'ing NRH --\n");
    return EXIT_SUCCESS;
}

int __diff_standard_attribute_headers(struct ntfs_standard_attribute_header* saha,
                                      struct ntfs_standard_attribute_header* sahb)
{
    fprintf_light_cyan(stdout, "\n-- Diff'ing SAH --\n");

    SAH_DIFF(attribute_type);
    SAH_DIFF(length);
    SAH_DIFF(non_resident_flag);
    SAH_DIFF(name_length);
    SAH_DIFF(name_offset);
    SAH_DIFF(flags);
    SAH_DIFF(attribute_id);
    SAH_DIFF(length_of_attribute);
    SAH_DIFF(offset_of_attribute);
    SAH_DIFF(indexed_flag);
    SAH_DIFF(padding);

    fprintf_light_cyan(stdout, "-- Finished diff'ing SAH --\n");
    return EXIT_SUCCESS;
}

int ntfs_parse_compare_data_run(uint8_t* data, uint64_t* offset,
                                uint64_t* length, int64_t* lcn)
{
    struct ntfs_data_run_header drh; 
    uint8_t len_size = 0;
    uint8_t offset_size = 0;

    memcpy(&drh, &(data[*offset]), sizeof(drh));
    *offset += 1;

    if (drh.packed_sizes)
    {
        offset_size = UPPER_NIBBLE(drh.packed_sizes);
        len_size = LOWER_NIBBLE(drh.packed_sizes);

        memcpy(((uint8_t*) length), &(data[*offset]), len_size);
        *offset += len_size;

        memcpy(((uint8_t*) lcn), &(data[*offset]), offset_size);
        *offset += offset_size;

        if (top_bit_set(((uint8_t *) lcn)[offset_size-1]))
            *lcn = sign_extend64(*lcn, highest_set_bit64(*lcn));
        
        return 1;
    }
    
    return 0;
}

/* handler for non-resident */
int ntfs_handle_compare_non_resident_data_attribute(uint8_t* bufa, uint64_t* offseta,
                                                    struct ntfs_standard_attribute_header* saha,
                                                    uint8_t* bufb, uint64_t* offsetb,
                                                    struct ntfs_standard_attribute_header* sahb,
                                                    int64_t partition_offset,
                                                    struct ntfs_boot_file* bootf)
{
    uint64_t real_sizea = 0, real_sizeb = 0;
    int64_t run_lcna = 0, run_lcnb = 0;
    int64_t run_lcn_bytesa = 0, run_lcn_bytesb = 0;
    int64_t prev_lcna = 0, prev_lcnb = 0;
    uint64_t run_lengtha = 0, run_lengthb = 0;
    uint64_t run_length_bytesa = 0, run_length_bytesb;
    struct ntfs_non_resident_header nrha, nrhb;

    fprintf_light_cyan(stdout, "\n-- Diff'ing data runs --\n");
    ntfs_read_non_resident_attribute_header(bufa, offseta, &nrha);
    ntfs_read_non_resident_attribute_header(bufb, offsetb, &nrhb);

    __diff_non_resident_headers(&nrha, &nrhb);

    real_sizea = nrha.real_size;
    real_sizeb = nrhb.real_size;

    *offseta += nrha.data_run_offset - sizeof(*saha) - sizeof(nrha);
    *offsetb += nrhb.data_run_offset - sizeof(*sahb) - sizeof(nrhb);

    while (ntfs_parse_compare_data_run(bufa, offseta, &run_lengtha, &run_lcna) &&
           ntfs_parse_compare_data_run(bufb, offsetb, &run_lengthb, &run_lcnb) &&
           real_sizea &&
           real_sizeb)
    {
        if (run_lengtha != run_lengthb)
        {
            fprintf_light_red(stdout, "Run length's differ [%"PRIu64" != %"
                                      PRIu64"].\n", run_lengtha, run_lengthb);
            fprintf_light_cyan(stdout, "-- Finished diff'ing data runs. --\n");
            return EXIT_FAILURE;
        }
        else
        {
            fprintf_yellow(stdout, "\tRun lengths are the same.\n");
        }

        if (run_lcna != run_lcnb)
        {
            fprintf_light_red(stdout, "Run LCN's differ [%"PRId64" != %"
                                      PRId64"].\n", run_lcna, run_lcnb);
            fprintf_light_cyan(stdout, "-- Finished diff'ing data runs. --\n");
            return EXIT_FAILURE;
        }
        else
        {
            fprintf_yellow(stdout, "\tRun LCN's are the same.\n");
        }

        run_length_bytesa = run_lengtha * bootf->bytes_per_sector * bootf->sectors_per_cluster;
        run_lcn_bytesa = ntfs_lcn_to_offset(bootf, partition_offset,
                                            prev_lcna + run_lcna);

        assert(prev_lcna + run_lcna > 0);
        assert(prev_lcna + run_lcna < 26214400);

        assert(prev_lcnb + run_lcnb > 0);
        assert(prev_lcna + run_lcnb < 26214400);

        run_length_bytesa = run_length_bytesa > real_sizea ? real_sizea : run_length_bytesa;
        run_length_bytesb = run_length_bytesb > real_sizeb ? real_sizeb : run_length_bytesb;

        real_sizea -= run_length_bytesa;
        real_sizeb -= run_length_bytesb;

        prev_lcna = prev_lcna + run_lcna;
        run_lengtha = 0;
        run_length_bytesa = 0;
        run_lcna = 0;
        run_lcn_bytesa = 0;

        prev_lcnb = prev_lcnb + run_lcnb;
        run_lengthb = 0;
        run_length_bytesb = 0;
        run_lcnb = 0;
        run_lcn_bytesb = 0;
    }

    fprintf_light_cyan(stdout, "-- Finished diff'ing data runs. --\n");
    return EXIT_SUCCESS;
}

/* dispatch handler for file name */
int ntfs_dispatch_compare_file_name_attribute(uint8_t* data, uint64_t* offset,
                                              char** name,
                                              struct ntfs_standard_attribute_header* sah)
{
    struct ntfs_file_name fname;
    char* file_name = malloc(512);
    char* file_namep = file_name;
    char** file_namepp = &file_namep;
    char file_name_encoded[512];
    char* file_name_encodedp = file_name_encoded;
    char** file_name_encodedpp = &file_name_encodedp;
    iconv_t cd = iconv_open("US-ASCII", "UTF-16");
    size_t outbytes = 512;
    size_t inbytes; 

    memset(file_name, 0, 512);
    memset(file_name_encoded, 0, 512);
    
    if (cd < 0)
    {
        fprintf_light_red(stderr, "Error creating conversion struct.\n");
        return -1;
    } 

    if (sah->attribute_type == 0x30) /* file name */
    {
        /* TODO: refactor */
        *offset += sah->offset_of_attribute - sizeof(*sah);
        fname = *((struct ntfs_file_name*) &(data[*offset]));
        *offset += sizeof(struct ntfs_file_name);

        //ntfs_print_file_name(&fname);

        memcpy(file_name_encoded, &(data[*offset]), 2*fname.name_len);
        *offset += 2*fname.name_len;

        file_name_encodedp = file_name_encoded;
        file_name_encodedpp = &file_name_encodedp;
        inbytes = 2*fname.name_len;

        if (iconv(cd, (char**) file_name_encodedpp, &inbytes, (char**) file_namepp, &outbytes) == (size_t) -1)
        {
            fprintf_light_red(stderr, "Error converting to wchar_t.\n");
            switch (errno)
            {
                case E2BIG:
                    fprintf_light_red(stderr, "There is not sufficient room at"
                                              " *outbuf\n");
                    break;
                case EILSEQ:
                    fprintf_light_red(stderr, "An invalid multibyte sequence "
                                              "has been encountered in the "
                                              "input.\n");
                    break;
                case EINVAL:
                    fprintf_light_red(stderr, "An incomplete multibyte "
                                              "sequence has been encountered "
                                              "in the input.\n");
                    break;
                default:
                    fprintf_light_red(stderr, "An unknown iconv error was "
                                              "encountered.\n");
            };

            return -1;
        }
        else
        {
            if (*name)
                free(*name);
            *name = file_name;
        }
    }

    iconv_close(cd);

    return EXIT_SUCCESS;
}

/* dispatch handler for data */
int ntfs_dispatch_compare_data_attribute(uint8_t* bufa, uint64_t* offseta,
                                         struct ntfs_standard_attribute_header* saha,
                                         uint8_t* bufb, uint64_t* offsetb,
                                         struct ntfs_standard_attribute_header* sahb,
                                         int64_t partition_offset,
                                         struct ntfs_boot_file* bootf)
{
    int i;
    if (saha->attribute_type != 0x80 &&
        sahb->attribute_type != 0x80)
    {
        fprintf_light_red(stderr, "Data handler, not a data attribute.\n");
        return EXIT_FAILURE;
    }
    
    if ((saha->flags & 0x0001) != 0x0000 &&
        (sahb->flags & 0x0001) != 0x0000) /* check compressed */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for compressed files"
                                  " yet.\n");
        return EXIT_FAILURE;
    }

    if ((saha->flags & 0x4000) != 0x0000 &&
        (sahb->flags & 0x4000) != 0x0000) /* check encrypted */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for encrypted files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    if ((saha->flags & 0x8000) != 0x0000 &&
        (sahb->flags & 0x8000) != 0x0000) /* check sparse */
    {
        fprintf_light_red(stdout, "NTFS: Error no support for sparse files "
                                  "yet.\n");
        return EXIT_FAILURE;
    }

    if (saha->non_resident_flag != sahb->non_resident_flag)
    {
        fprintf_light_red(stdout, "non-resident mismatch.\n");
        return EXIT_FAILURE;
    }

    if (saha->non_resident_flag)
    {
        ntfs_handle_compare_non_resident_data_attribute(bufa, offseta, saha,
                                                        bufb, offsetb, sahb,
                                                        partition_offset, bootf);
    }
    else
    {
        /* show extra bytes */
        if (saha->length_of_attribute < sahb->length_of_attribute)
        {
            fprintf_light_blue(stdout, "Got new resident bytes:\n");
            *offsetb += sahb->offset_of_attribute - sizeof(*sahb) + saha->length_of_attribute;
            for (i = 0; i < sahb->length_of_attribute - saha->length_of_attribute; i++)
            {
                fputc(bufb[*offsetb + i], stdout);
            }
            fprintf(stdout, "\n");
        }
    }

    return EXIT_SUCCESS;
}

int ntfs_compare_attribute_dispatcher(uint8_t* bufa, uint8_t* bufb,
                                      uint64_t* offseta, uint64_t* offsetb,
                                      char** fnamea, char** fnameb,
                                      struct ntfs_standard_attribute_header* saha,
                                      struct ntfs_standard_attribute_header* sahb,
                                      int64_t partition_offset, struct ntfs_boot_file* bootf)
{
    int ret = 1;
    uint64_t old_offseta = *offseta;
    uint64_t old_offsetb = *offsetb;

    if (saha->attribute_type != sahb->attribute_type)
    {
        fprintf_light_red(stdout, "Attribute types differ\n");
        return 0;
    }

    if (saha->attribute_type == 0x30)
    {
        fprintf_light_cyan(stdout, "\n-- Diff'ing file name --\n");
        if (ntfs_dispatch_file_name_attribute(bufa, offseta, fnamea, saha))
           ret = -1;
        if (ntfs_dispatch_file_name_attribute(bufb, offsetb, fnameb, sahb))
           ret = -1;
        if (!(*fnamea == *fnameb) && strcmp(*fnamea, *fnameb))
        {
            fprintf_light_red(stdout, "fname mismatch.\n");
            fprintf_light_blue(stdout, "\t%ls != %ls\n", *fnamea, *fnameb);
        }
        else
        {
            fprintf_yellow(stdout, "fname matches.\n");
        }
        fprintf_light_cyan(stdout, "-- Finished Diff'ing file name --\n");
        *offseta = old_offseta + saha->length - sizeof(*saha);
        *offsetb = old_offsetb + sahb->length - sizeof(*sahb);
    }
    else if (saha->attribute_type == 0x80)
    {
        fprintf_light_yellow(stdout, "Dispatching data attribute.\n");
        if (ntfs_dispatch_compare_data_attribute(bufa, offseta, saha,
                                                 bufb, offsetb, sahb,
                                                 partition_offset, bootf))
            ret = -1;
        *offseta = old_offseta + saha->length - sizeof(*saha);
        *offsetb = old_offsetb + sahb->length - sizeof(*sahb);
    }
    else
    {
        *offseta = old_offseta + saha->length - sizeof(*saha);
        *offsetb = old_offsetb + sahb->length - sizeof(*sahb);
        fprintf_light_yellow(stdout, "Dispatching unhandled attribute.\n");
    }

    if (*((int32_t*) &(bufa[*offseta])) == -1)
        ret = 0;

    if (*((int32_t*) &(bufb[*offsetb])) == -1)
        ret = 0;

    return ret;
}

int ntfs_diff_raw_file_records(uint8_t* bufa, uint8_t* bufb,
                               int64_t partition_offset,
                               struct ntfs_boot_file* bootf)
{
    struct ntfs_file_record reca, recb;
    struct ntfs_update_sequence seqa, seqb;
    struct ntfs_standard_attribute_header saha, sahb;
    char* fnamea = NULL, *fnameb = NULL;
    uint64_t offseta = 0, offsetb = 0, counter = 0;

    ntfs_read_file_record_header(bufa, &offseta, &reca);
    ntfs_read_update_sequence(bufa, &offseta, reca.size_usn,
                              reca.usn_num, &seqa);
    ntfs_fixup_data(bufa, ntfs_file_record_size(bootf), &seqa);

    ntfs_read_file_record_header(bufb, &offsetb, &recb);
    ntfs_read_update_sequence(bufb, &offsetb, recb.size_usn,
                              recb.usn_num, &seqb);
    ntfs_fixup_data(bufb, ntfs_file_record_size(bootf), &seqb);

    __diff_file_records(&reca, &recb);

    offseta = reca.offset_first_attribute;
    offsetb = recb.offset_first_attribute;

    while (ntfs_read_attribute_header(bufa, &offseta, &saha) == 0 &&
           ntfs_read_attribute_header(bufb, &offsetb, &sahb) == 0 &&
           counter < 1024)
    {
        __diff_standard_attribute_headers(&saha, &sahb);
        if (ntfs_compare_attribute_dispatcher(bufa, bufb, &offseta, &offsetb,
                                              &fnamea, &fnameb, &saha, &sahb,
                                              partition_offset, bootf)
            == 0)
            break;
        counter++;
    }

    return EXIT_SUCCESS;
}


int ntfs_diff_file_record_buffs(uint8_t* bufa, uint8_t* bufb,
                                int64_t partition_offset,
                                struct ntfs_boot_file* bootf)
{
    return ntfs_diff_raw_file_records(bufa, bufb,partition_offset, bootf);
}

int ntfs_diff_file_records(FILE* disk, uint64_t recorda, uint64_t recordb,
                           int64_t partition_offset,
                           struct ntfs_boot_file* bootf,
                           struct bitarray* bits)
{
    uint64_t file_record_size = ntfs_file_record_size(bootf);
    uint8_t* data_a = malloc(file_record_size);
    uint8_t* data_b = malloc(file_record_size);

    if (data_a == NULL)
    {
        fprintf_light_red(stderr, "Error malloc()ing data_a.\n");
        return EXIT_FAILURE;
    }

    if (data_b == NULL)
    {
        fprintf_light_red(stderr, "Error malloc()ing data_b.\n");
        return EXIT_FAILURE;
    }

    ntfs_read_file_record(disk, recorda, partition_offset, bootf, bits, data_a, NULL);
    ntfs_read_file_record(disk, recordb, partition_offset, bootf, bits, data_b, NULL);

    ntfs_diff_raw_file_records(data_a, data_b, partition_offset, bootf);

    free(data_a);    
    free(data_b);

    return EXIT_SUCCESS;
}

int ntfs_serialize_fs(struct ntfs_boot_file* bootf, struct bitarray* bits,
                      int64_t partition_offset, uint32_t pte_num,
                      char* mount_point, FILE* serializedf)
{
    int32_t num_block_groups = 0;
    int32_t num_files = -1;
    struct bson_info* serialized;
    struct bson_info* sectors;
    struct bson_kv value;

    serialized = bson_init();
    sectors = bson_init();

    value.type = BSON_STRING;
    value.size = strlen("fs");
    value.key = "type";
    value.data = "fs";

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "pte_num";
    value.data = &(pte_num);

    bson_serialize(serialized, &value);

    value.type = BSON_STRING;
    value.size = strlen("ntfs");
    value.key = "fs";
    value.data = "ntfs";

    bson_serialize(serialized, &value);

    value.type = BSON_STRING;
    value.key = "mount_point";
    value.size = strlen(mount_point);
    value.data = mount_point;

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "num_block_groups";
    value.data = &(num_block_groups);

    bson_serialize(serialized, &value);

    value.type = BSON_INT32;
    value.key = "num_files";
    value.data = &(num_files);

    bson_serialize(serialized, &value);

    value.type = BSON_INT64;
    value.key = "superblock_sector";
    partition_offset /= SECTOR_SIZE;
    value.data = &(partition_offset);

    bson_serialize(serialized, &value);

    value.type = BSON_INT64;
    value.key = "superblock_offset";
    partition_offset %= SECTOR_SIZE;
    value.data = &(partition_offset);

    bson_serialize(serialized, &value);

    value.key = "superblock";
    value.type = BSON_BINARY;
    value.size = sizeof(struct ntfs_boot_file);
    value.subtype = BSON_BINARY_GENERIC;
    value.data = bootf;

    bson_serialize(serialized, &value);

    bson_finalize(serialized);
    bson_writef(serialized, serializedf);
    bson_cleanup(sectors);
    bson_cleanup(serialized);

    return EXIT_SUCCESS;
}

int ntfs_serialize_file_record(FILE* disk, struct ntfs_boot_file* bootf,
                               struct bitarray* bits,
                               int64_t partition_offset, char* prefix,
                               FILE* serializedf, uint8_t* data,
                               struct bson_info* bson)
{
    uint64_t fsize, data_offset = 0, stream_len;
    bool is_dir;
    struct bson_kv value;
    struct ntfs_file_record rec;
    struct ntfs_file_name fdata;
    struct ntfs_update_sequence seq;
    struct ntfs_standard_attribute_header sah;

    ntfs_read_file_record_header(data, &data_offset, &rec);
    ntfs_read_update_sequence(data, &data_offset, rec.size_usn,
                              rec.usn_num, &seq);
    ntfs_fixup_data(data, ntfs_file_record_size(bootf), &seq);

    data_offset = 0;
    is_dir = (rec.flags & 0x02) == 0x02;

    if (ntfs_get_attribute(data, &fdata, &data_offset, NTFS_FILE_NAME))
    {
        fprintf_light_red(stderr, "Failed getting NTFS_FILE_NAME attr.\n");
        return EXIT_FAILURE;
    }

    data_offset = 0;

    if (!is_dir && ntfs_get_attribute(data, &sah, &data_offset, NTFS_DATA))
    {
        fprintf_light_red(stderr, "Failed getting NTFS_DATA attr.\n");
        return EXIT_FAILURE;
    }

    ntfs_get_size(data, &sah, &data_offset, &fsize);

    value.type = BSON_STRING;
    if (strlen(prefix) > 1 && is_dir)
        value.size = strlen(prefix) - 1;
    else
        value.size = strlen(prefix);
    value.key = "path";
    value.data = prefix;

    bson_serialize(bson, &value);

    value.type = BSON_BOOLEAN;
    value.key = "is_dir";
    value.data = &is_dir;

    bson_serialize(bson, &value);

    value.type = BSON_INT64;
    value.key = "size";
    value.data = &(fsize);

    bson_serialize(bson, &value);

    value.type = BSON_BINARY;
    value.subtype = BSON_BINARY_GENERIC;
    value.size = ntfs_file_record_size(bootf);
    value.key = "inode";
    value.data = data;

    bson_serialize(bson, &value);

    data_offset = 0;

    if (!is_dir && ntfs_get_attribute(data, &sah, &data_offset, NTFS_DATA))
    {
        fprintf_light_red(stderr, "Failed getting NTFS_DATA attr.\n");
        return EXIT_FAILURE;
    }

    if (!is_dir)
    {
        ntfs_dispatch_data_attribute(data, &data_offset, prefix, &sah, bootf, bits,
                                     partition_offset, disk, false, NULL, false,
                                     bson, true, &stream_len);
        bson_finalize(bson);
        bson_writef(bson, serializedf);
        bson_cleanup(bson);
    }

    if (is_dir)
    {
        /* walk index allocation table */
        fprintf_light_red(stderr, "--- Handling directory [%s] ---\n", prefix);
        data_offset = 0;


        if (ntfs_get_attribute(data, &sah, &data_offset, NTFS_INDEX_ROOT))
        {
            fprintf_light_red(stderr, "Failed getting NTFS_INDEX_ROOT attr.\n");
        }
        else
        {
            ntfs_dispatch_index_root_attribute(data, (uint64_t*) &data_offset,
                                               prefix, &sah, bootf, bits,
                                               partition_offset, disk,
                                               bson, serializedf);
        }

        data_offset = 0;

        if (ntfs_get_attribute(data, &sah, &data_offset, NTFS_INDEX_ALLOCATION))
        {
            fprintf_light_red(stderr, "Failed getting NTFS_INDEX_ALLOCATION attr.\n");
        }
        else
        {
            ntfs_dispatch_index_allocation_attribute(data, (uint64_t*) &data_offset,
                                                     prefix, &sah, bootf, bits,
                                                     partition_offset, disk,
                                                     bson, serializedf);
        }

    }

    return EXIT_SUCCESS;
}

int ntfs_serialize_fs_tree(FILE* disk, struct ntfs_boot_file* bootf, struct bitarray* bits,
                           int64_t partition_offset, char* mount_point,
                           FILE* serializedf)
{
    uint8_t data[ntfs_file_record_size(bootf)];
    struct bson_info* bson = bson_init();

    if (ntfs_read_file_record(disk, 5, partition_offset, bootf, bits,
                              data, bson) == 0)
    {
        fprintf_light_red(stderr, "Failed reading file record 5\n");
        return EXIT_FAILURE;
    }

    ntfs_serialize_file_record(disk, bootf, bits, partition_offset, 
                               mount_point, serializedf, data, bson);

    return EXIT_SUCCESS;
}
