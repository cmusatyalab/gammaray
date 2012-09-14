#ifndef __STREAM_ANALYZER_REDIS_H
#define __STREAM_ANALYZER_REDIS_H

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

#define REDIS_INODE_INSERT "RPUSH inode:%"PRIu64" file:"PRIu64
#define REDIS_INODE_LGET "LRANGE inode:%"PRIu64" 0 -1"

#define REDIS_FILE_SECTOR_INSERT "HSET file:%"PRIu64" %s %b"
#define REDIS_FILE_SECTOR_GET "HGET file:%"PRIu64" %s"
#define REDIS_FILES_INSERT "RPUSH files:%"PRIu64" file:%"PRIu64
#define REDIS_FILES_LGET "LRANGE files:%"PRIu64" 0 -1"
#define REDIS_FILES_SECTOR_INSERT "SET sector:%"PRIu64" lfiles:%"PRIu64

#define REDIS_EXTENT_SECTOR_INSERT "HSET extent:%"PRIu64" %s %b"
#define REDIS_EXTENT_SECTOR_GET "HGET extent:%"PRIu64" %s"
#define REDIS_EXTENTS_INSERT "RPUSH extents:%"PRIu64" extent:%"PRIu64
#define REDIS_EXTENTS_LGET "LRANGE extents:%"PRIu64" 0 -1"
#define REDIS_EXTENTS_SECTOR_INSERT "SET sector:%"PRIu64" lextents:%"PRIu64

#define REDIS_DIR_SECTOR_INSERT "HSET dirdata:%"PRIu64" %s %b"
#define REDIS_DIR_SECTOR_GET "HGET dirdata:%"PRIu64" %s"
#define REDIS_DIR_INSERT "SET sector:%"PRIu64" dirdata:%"PRIu64

#define REDIS_ASYNC_QUEUE_PUSH "LPUSH writequeue %b"
#define REDIS_ASYNC_QUEUE_POP "BRPOP writequeue"

struct kv_store;
struct thread_job;

void redis_print_version();

struct kv_store* redis_init(char* db, bool background_flush);
void redis_shutdown(struct kv_store* store);

int redis_get_fcounter(struct kv_store* handle, uint64_t* counter);
int redis_set_fcounter(struct kv_store* handle, uint64_t counter);

int redis_flush_pipeline(struct kv_store* handle);
int redis_enqueue_pipelined(struct kv_store* handle, uint64_t sector_num,
                            const uint8_t* data, size_t len);
int redis_dequeue(struct kv_store* handle, uint64_t sector_num,
                  uint8_t* data, size_t* len);
int redis_publish(struct kv_store* handle, char* channel, uint8_t* data,
                  size_t len);

int redis_reverse_pointer_set(struct kv_store* handle, const char* fmt,
                              uint64_t src, uint64_t dst);
int redis_hash_field_set(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, const uint8_t* data,
                         size_t len);
int redis_hash_field_get(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, uint8_t* data,
                         size_t* len);
int redis_reverse_file_data_pointer_set(struct kv_store* handle,
                                        uint64_t src, uint64_t start,
                                        uint64_t end, uint64_t dst);
int redis_sector_lookup(struct kv_store* store, uint64_t sector, uint8_t* data,
                        size_t* len);
int redis_list_get(struct kv_store* handle, char* fmt, uint64_t src,
                   uint8_t** result[], size_t* len);
void redis_free_list(uint8_t* list[], size_t len);

int redis_async_write_enqueue(struct kv_store* handle, uint8_t* data,
                                                       size_t len);
int redis_async_write_dequeue(struct kv_store* handle, uint8_t* data,
                                                       size_t* len);
#endif
