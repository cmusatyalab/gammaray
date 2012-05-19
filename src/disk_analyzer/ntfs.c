#include "color.h"
#include "ntfs.h"
#include "util.h"

#include <errno.h>
#include <iconv.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>




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

int ntfs_print_data_run(struct ntfs_data_run_header* header, FILE* disk)
{
    fprintf_light_yellow(stdout, "data_run.raw: %x\n", header->packed_sizes);
    fprintf_yellow(stdout, "data_run.length_size: %u\n", UPPER_NIBBLE(header->packed_sizes));
    fprintf_yellow(stdout, "data_run.start_size: %u\n", LOWER_NIBBLE(header->packed_sizes));
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



/* read FILE record */
uint8_t* ntfs_read_file_record(FILE* disk, int64_t* offset,
                               struct ntfs_boot_file* bootf)
{
    uint64_t record_size = bootf->clusters_per_mft_record > 0 ?
                           bootf->clusters_per_mft_record *
                           bootf->sectors_per_cluster *
                           bootf->bytes_per_sector :
                           2 << -1 * (bootf->clusters_per_mft_record + 1);

    uint8_t* data = malloc(record_size);

    if (data == NULL)
    {
        fprintf_light_red(stderr, "Error malloc()ing to read file record.\n");
        return NULL;
    }

    if (fseeko(disk, *offset, SEEK_SET))
    {
        fprintf_light_red(stderr, "Error seeking to FILE record.\n");
        free(data);
        return NULL;
    }

    if (fread(data, 1, record_size, disk) != record_size)
    {
        fprintf_light_red(stderr, "Error reading FILE record data.\n");
        free(data);
        return NULL;
    }

    if (strncmp((char*) data, "FILE", 4) != 0)
    {
        fprintf_light_cyan(stdout, "FILE magic bytes mistmatch.\n");
        free(data);
        return NULL;
    }

    *offset += record_size;

    return data;
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
                              struct ntfs_file_record* rec,
                              struct ntfs_update_sequence* seq)
{
    uint8_t* buf = malloc(2*(rec->size_usn) - 2);
    memcpy(buf, &(data[*offset]), 2*(rec->size_usn) - 2);
    *offset += 2*(rec->size_usn) - 2;

    seq->usn_num = rec->usn_num;
    seq->usn_size = 2*(rec->size_usn) - 2;
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
    fprintf_light_blue(stdout, "-- BEFORE FIXUP --\n");
    hexdump(data, 1024);
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

    fprintf_light_blue(stdout, "-- AFTER FIXUP --\n");
    hexdump(data, 1024);
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

FILE* ntfs_create_reconstructed_file(wchar_t* name)
{
    FILE* reconstructed = NULL;
    char fname[1024] = { 0 };

    if (name)
    {
        strcat(fname, "/tmp/win7/");
        if (wcstombs(fname + strlen(fname), name, 1024 - strlen(fname)) == -1)
        {
            fprintf_light_red(stderr, "Could not create file name.\n");
            return NULL;
        }

        fprintf_light_green(stdout, "Dynamic path: %s\n", fname);

        /* create "versions" of files depending on number of valid file records */
        /* TODO: could loop forever */
        while ((reconstructed = fopen(fname, "wx")) == NULL)
        {
            fprintf_light_red(stderr, "Error creating file %s\n", fname);
            fprintf_light_red(stderr, "\t%s\n", strerror(errno));
            strcat(fname, "0");
        }
    }

    return reconstructed;
}

/* handler for resident */
int ntfs_handle_resident_data_attribute(uint8_t* data, uint64_t* offset,
                                        uint8_t* buf, uint64_t buf_len,
                                        wchar_t* name,
                                        struct ntfs_standard_attribute_header* sah)
{
    FILE* reconstructed = ntfs_create_reconstructed_file(name);
    
    fprintf_yellow(stdout, "\tData is resident.\n");
    fprintf_white(stdout, "\tsah->offset_of_attribute: %x\tsizeof(sah) %x\n", sah->offset_of_attribute, sizeof(*sah));
    fprintf_green(stdout, "\tSeeking to %d\n", sah->offset_of_attribute - sizeof(*sah));

    ntfs_read_attribute_data(data, offset, buf, buf_len, sah);
  
    if (reconstructed)
    {
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


/* handler for non-resident */
/* TODO */


/* dispatch handler for file name */
int ntfs_dispatch_file_name_attribute(uint8_t* data, uint64_t* offset,
                                    wchar_t** name,
                                    struct ntfs_standard_attribute_header* sah)
{
    struct ntfs_file_name fname;
    wchar_t* file_name = malloc(sizeof(wchar_t) * 512);
    wchar_t* file_namep = file_name;
    wchar_t** file_namepp = &file_namep;
    char file_name_encoded[512];
    char* file_name_encodedp = file_name_encoded;
    char** file_name_encodedpp = &file_name_encodedp;
    iconv_t cd = iconv_open("WCHAR_T", "UTF-16");
    size_t outbytes = sizeof(wchar_t) * 512;
    size_t inbytes; 

    memset(file_name, 0, sizeof(wchar_t) * 512);
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

        ntfs_print_file_name(&fname);

        memcpy(file_name_encoded, &(data[*offset]), 2*fname.name_len);
        *offset += 2*fname.name_len;

        file_name_encodedp = file_name_encoded;
        file_name_encodedpp = &file_name_encodedp;
        inbytes = 2*fname.name_len;

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
                    fprintf_light_red(stderr, "There is not sufficient room at *outbuf\n");
                    break;
                case EILSEQ:
                    fprintf_light_red(stderr, "An invalid multibyte sequence has been encountered in the input.\n");
                    break;
                case EINVAL:
                    fprintf_light_red(stderr, "An incomplete multibyte sequence has been encountered in the input.\n");
                    break;
                default:
                    fprintf_light_red(stderr, "An unknown iconv error was encountered.\n");
            };

            return -1;
        }
        else
        {
            fprintf_light_cyan(stdout, "found fname[len=%d, namespace=%s]: "
                                       "%ls\n", wcslen(file_name),
                                       ntfs_namespace(fname.fnamespace),
                                       file_name);

            if (ntfs_ignore_file(file_name))
            {
                fprintf(stdout, "ignoring file.\n");
                iconv_close(cd);
                return EXIT_SUCCESS;
            }

            if (*name)
                free(*name);
            *name = file_name;
        }
    }

    iconv_close(cd);

    return EXIT_SUCCESS;
}

/* dispatch handler for data */
int ntfs_dispatch_data_attribute(uint8_t* data, uint64_t* offset,
                                 wchar_t* name,
                                 struct ntfs_standard_attribute_header* sah)
{
    uint8_t resident_buffer[4096];

    if (sah->attribute_type != 0x80)
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
        fprintf_light_cyan(stderr, "Currently not handling non-resident data.\n");
    }
    else
    {
        ntfs_handle_resident_data_attribute(data, offset, resident_buffer, 4096,
                                            name, sah);
        exit(0);
    }

    return EXIT_SUCCESS;
}


/* attribute dispatcher */
int ntfs_attribute_dispatcher(uint8_t* data, uint64_t* offset, wchar_t** fname,
                              struct ntfs_standard_attribute_header* sah)
{
    int ret = 1;
    uint64_t old_offset = *offset;

    if (sah->attribute_type == 0x30)
    {
        fprintf_light_yellow(stdout, "Dispatching file name attribute.\n");
        if (ntfs_dispatch_file_name_attribute(data, offset, fname, sah))
           ret = -1;
        *offset = old_offset + sah->length - sizeof(*sah);
    }
    else if (sah->attribute_type == 0x80)
    {
        fprintf_light_yellow(stdout, "Dispatching data attribute.\n");
        if (ntfs_dispatch_data_attribute(data, offset, *fname, sah))
            ret = -1;
        *offset = old_offset + sah->length - sizeof(*sah);
    }
    else
    {
        *offset += sah->length - sizeof(*sah);
        fprintf_light_yellow(stdout, "Dispatching unhandled attribute.\n");
        if (*((uint32_t*) &(data[*offset])) == 0xffffff)
            ret = 0;
    }

    if (*((int32_t*) &(data[*offset])) == -1)
        ret = 0;

    return ret;
}




/* meta-walk MFT */
int ntfs_walk_mft(FILE* disk, struct ntfs_boot_file* bootf,
                  int64_t partition_offset)
{
    struct ntfs_file_record rec;
    struct ntfs_update_sequence seq;
    struct ntfs_standard_attribute_header sah;
    uint8_t* data = NULL;
    int64_t file_record_offset;
    uint64_t data_offset = 0;
    wchar_t* fname = NULL;
    int counter = 0;

    file_record_offset =
        ntfs_lcn_to_offset(bootf, partition_offset, bootf->lcn_mft); 

    fprintf_light_red(stdout, "Current file_record_offset: %"PRId64"\n", file_record_offset);
    while ((data = ntfs_read_file_record(disk, &file_record_offset, bootf)) !=
                NULL)
    {
        data_offset = 0;
        fprintf_light_red(stdout, "Current file_record_offset: %"PRId64"\n", file_record_offset);
        ntfs_read_file_record_header(data, &data_offset, &rec);
        ntfs_print_file_record(&rec);
        ntfs_read_update_sequence(data, &data_offset, &rec, &seq);
        ntfs_fixup_data(data, 1024, &seq);
        
        data_offset = rec.offset_first_attribute;
        counter = 0;
        while (ntfs_read_attribute_header(data, &data_offset, &sah) == 0 &&
               counter < 1024)
        {
            ntfs_print_standard_attribute_header(&sah);

            if (ntfs_attribute_dispatcher(data, &data_offset, &fname, &sah) ==0)
                break;
            counter++;
        }
        if (data)
        {
            free(data);
            data = NULL;
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
