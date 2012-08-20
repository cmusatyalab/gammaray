#ifndef __STREAM_ANALYZER_REDIS_H
#define __STREAM_ANALYZER_REDIS_H

#include <inttypes.h>

#include "hiredis.h"

struct kv_store
{
    redisContext* connection;
    uint64_t outstanding_pipelined_cmds;
};

struct kv_store* redis_init(char* db);
int redis_enqueue(struct kv_store* handle, uint64_t sector_num,
                  const uint8_t* data, size_t len);
void redis_enqueue_pipelined(struct kv_store* handle, uint64_t sector_num,
                             const uint8_t* data, size_t len);
int redis_flush_pipeline(struct kv_store* handle);
int redis_dequeue(struct kv_store* handle, uint64_t sector_num,
                  uint8_t* data, size_t* len);
int redis_publish(struct kv_store* handle, char* channel, uint8_t* data,
                  size_t len);
void redis_shutdown(struct kv_store* store);

#endif
