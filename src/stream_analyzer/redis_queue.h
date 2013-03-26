#ifndef __STREAM_ANALYZER_REDIS_H
#define __STREAM_ANALYZER_REDIS_H

#include "bitarray.h"
#include "qemu_common.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

#define REDIS_MBR_SECTOR_INSERT "HSET mbr:%"PRIu64" %s %b"
#define REDIS_MBR_SECTOR_GET "HGET mbr:%"PRIu64" %s"
#define REDIS_MBR_INSERT "SET sector:%"PRIu64" mbr:%"PRIu64

#define REDIS_SUPERBLOCK_SECTOR_INSERT "HSET fs:%"PRIu64" %s %b"
#define REDIS_SUPERBLOCK_SECTOR_GET "HGET fs:%"PRIu64" %s"
#define REDIS_SUPERBLOCK_INSERT "SET sector:%"PRIu64" fs:%"PRIu64

#define REDIS_BGD_SECTOR_INSERT "HSET bgd:%"PRIu64" %s %b"
#define REDIS_BGD_SECTOR_GET "HGET bgd:%"PRIu64" %s"
#define REDIS_BGDS_INSERT "RPUSH bgds:%"PRIu64" bgd:%"PRIu64
#define REDIS_BGDS_LGET "LRANGE bgds:%"PRIu64" 0 -1"
#define REDIS_BGDS_SECTOR_INSERT "SET sector:%"PRIu64" lbgds:%"PRIu64

#define REDIS_BLOCKDMAP_INSERT "SET sector:%"PRIu64" bgd:%"PRIu64
#define REDIS_BLOCKIMAP_INSERT "SET sector:%"PRIu64" bgd:%"PRIu64

#define REDIS_INODE_INSERT "RPUSH inode:%"PRIu64" file:%"PRIu64
#define REDIS_INODE_LGET "LRANGE inode:%"PRIu64" 0 -1"

#define REDIS_FILE_SECTOR_INSERT "HSET file:%"PRIu64" %s %b"
#define REDIS_FILE_SECTOR_GET "HGET file:%"PRIu64" %s"
#define REDIS_FILE_SECTORS_INSERT "RPUSH filesectors:%"PRIu64" sector:%"PRId64
#define REDIS_FILE_SECTORS_LGET "LRANGE filesectors:%"PRIu64" 0 -1"
#define REDIS_FILE_SECTORS_LGET_VAR "LRANGE filesectors:%"PRIu64" %"PRIu64" %"PRIu64
#define REDIS_FILE_SECTORS_LAST_SECTOR "LINDEX filesectors:%"PRIu64" -1"
#define REDIS_FILE_SECTORS_LLEN "LLEN filesectors:%"PRIu64
#define REDIS_FILE_SECTORS_LSET "LSET filesectors:%"PRIu64" %"PRIu64" sector:%"PRId64
#define REDIS_FILE_SECTORS_DELETE "DEL filesectors:%"PRIu64
#define REDIS_FILES_INSERT "RPUSH files:%"PRIu64" file:%"PRIu64
#define REDIS_FILES_LGET "LRANGE files:%"PRIu64" 0 -1"
#define REDIS_FILES_SECTOR_INSERT "SET sector:%"PRIu64" lfiles:%"PRIu64
#define REDIS_FILES_SECTOR_DELETE "DEL sector:%"PRIu64

#define REDIS_PATH_SET "SET path:%b %"PRIu64
#define REDIS_PATH_GET "GET path:%b"

#define REDIS_EXTENT_SECTOR_INSERT "HSET extent:%"PRIu64" %s %b"
#define REDIS_EXTENT_SECTOR_GET "HGET extent:%"PRIu64" %s"
#define REDIS_EXTENTS_INSERT "RPUSH extents:%"PRIu64" extent:%"PRIu64
#define REDIS_EXTENTS_LGET "LRANGE extents:%"PRIu64" 0 -1"
#define REDIS_EXTENTS_LINSERT "LINSERT extents:%"PRIu64" BEFORE %"PRIu64" extent:%"PRIu64
#define REDIS_EXTENTS_LLEN "LLEN extents:%"PRIu64
#define REDIS_EXTENTS_SECTOR_INSERT "SET sector:%"PRIu64" extent:%"PRIu64

#define REDIS_DIR_SECTOR_INSERT "HSET dirdata:%"PRIu64" %s %b"
#define REDIS_DIR_SECTOR_GET "HGET dirdata:%"PRIu64" %s"
#define REDIS_DIR_FILES_INSERT "RPUSH dirlist:%"PRIu64" %b"
#define REDIS_DIR_FILES_LGET "LRANGE dirlist:%"PRIu64" 0 -1"
#define REDIS_DIR_INSERT "SET sector:%"PRIu64" dirdata:%"PRIu64

#define REDIS_ASYNC_QUEUE_PUSH "LPUSH writequeue %b"
#define REDIS_ASYNC_QUEUE_POP "BRPOP writequeue 0"

#define REDIS_RESET_CREATED "DEL createset"
#define REDIS_RESET_DELETED "DEL deleteset"
#define REDIS_CREATED_SET_ADD "SADD createset %"PRIu64
#define REDIS_CREATED_SET_REMOVE "SREM createset %"PRIu64
#define REDIS_DELETED_SET_ADD "SADD deleteset %"PRIu64
#define REDIS_DELETED_SET_REMOVE "SREM deleteset %"PRIu64
#define REDIS_LIST_DELETED "SDIFF deleteset createset"
#define REDIS_LIST_CREATED "SDIFF createset deleteset"

#define REDIS_LOAD_RECORD "SET sector:%"PRIu64" load:%"PRIu64
#define REDIS_LOAD_LRECORDS "SET sector:%"PRIu64" loadlist:%"PRIu64
#define REDIS_LOAD_LRECORDS_INSERT "RPUSH loadlist:%"PRIu64" load:%"PRIu64
#define REDIS_GET_LRECORDS "LRANGE loadlist:%"PRIu64" 0 -1"

struct kv_store;
struct thread_job;

void redis_print_version();

struct kv_store* redis_init(char* db, bool background_flush);
void redis_shutdown(int clear, struct kv_store* store);

int redis_get_fcounter(struct kv_store* handle, uint64_t* counter);
int redis_set_fcounter(struct kv_store* handle, uint64_t counter);

int redis_flush_pipeline(struct kv_store* handle);
int redis_enqueue_pipelined(struct kv_store* handle, uint64_t sector_num,
                            const uint8_t* data, size_t len);
int redis_dequeue(struct kv_store* handle, uint64_t sector_num,
                  uint8_t* data, size_t* len);
int redis_delqueue_pipelined(struct kv_store* handle, uint64_t sector_num);
int redis_publish(struct kv_store* handle, char* channel, uint8_t* data,
                  size_t len);

int redis_reverse_pointer_set(struct kv_store* handle, const char* fmt,
                              uint64_t src, int64_t dst);
int redis_hash_field_set(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, const uint8_t* data,
                         size_t len);
int redis_hash_field_get(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, uint8_t* data,
                         size_t* len);
int redis_reverse_file_data_pointer_set(struct kv_store* handle,
                                        int64_t src, uint64_t start,
                                        uint64_t end, uint64_t dst);
int redis_sector_lookup(struct kv_store* store, uint64_t sector, uint8_t* data,
                        size_t* len);
int redis_binary_insert(struct kv_store* handle, const char* fmt,
                        uint64_t src, const uint8_t* data, size_t len);
int redis_list_get(struct kv_store* handle, char* fmt, uint64_t src,
                   uint8_t** result[], size_t* len);
int redis_list_get_var(struct kv_store* handle, char* fmt, uint64_t src,
                       uint8_t** result[], size_t* len, 
                       int64_t start, int64_t end);
int redis_list_len(struct kv_store* handle, char* fmt, uint64_t src,
                   uint64_t* len);
int redis_list_set(struct kv_store* handle, char* fmt, uint64_t src,
                   uint64_t index, int64_t value);
void redis_free_list(uint8_t* list[], size_t len);

int redis_last_file_sector(struct kv_store* handle, uint64_t id, 
                           uint64_t* sector);

int redis_set_reset(struct kv_store* handle);
int redis_set_add(struct kv_store* handle, char* fmt, uint64_t id);
int redis_set_remove(struct kv_store* handle, char* fmt, uint64_t id,
                     uint64_t* result);

int redis_async_write_enqueue(struct kv_store* handle, struct bitarray* bits,
                              int64_t sector, uint8_t* data, size_t len);
int redis_async_write_dequeue(struct kv_store* handle,
                              struct qemu_bdrv_write* write);

int redis_path_set(struct kv_store* handle, const uint8_t* path, size_t len,
                   uint64_t id);
int redis_path_get(struct kv_store* handle, const uint8_t* path, size_t len,
                   uint64_t* id);
int redis_metadata_set(struct kv_store* handle, const uint8_t* data,
                       size_t len);
int redis_metadata_get(struct kv_store* handle, uint8_t** data,
                       size_t* len);
int redis_delete_key(struct kv_store* handle, char* fmt, uint64_t id);
#endif
