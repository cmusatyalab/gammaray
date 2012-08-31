#include "redis_queue.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/***** Helper Functions, not exposed *****/
int check_redis_return(redisContext* c, redisReply* reply)
{
    if (reply == NULL || ((int) reply) == REDIS_ERR)
    {
        switch(c->err)
        {
            case REDIS_ERR_IO:
                break;
            case REDIS_ERR_EOF:
                break;
            case REDIS_ERR_PROTOCOL:
                break;
            case REDIS_ERR_OTHER:
                break;
            default:
                break;
        };
        return EXIT_FAILURE;
    }
    freeReplyObject(reply);
    return EXIT_SUCCESS;
}

int redis_select(struct kv_store* handle, char* db)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "SELECT %s", db);
    return check_redis_return(handle->connection, reply);
}

int redis_flush_pipeline(struct kv_store* handle)
{
    redisReply* reply;
    while (handle->outstanding_pipelined_cmds)
    {
        redisGetReply(handle->connection, (void**) &reply);
        if(check_redis_return(handle->connection, reply))
        {
            return EXIT_FAILURE;
        }
        handle->outstanding_pipelined_cmds--;
    }
    return EXIT_SUCCESS;
}

/***** Core API *****/
struct kv_store* redis_init(char* db)
{
    struct timeval timeout = { 1, 500000 };
    struct kv_store* handle = (struct kv_store*)
                              malloc(sizeof(struct kv_store));
    if (handle)
    {
        handle->connection = redisConnectWithTimeout((char*)"127.0.0.1", 6379,
                                              timeout);
        handle->outstanding_pipelined_cmds = 0;
        if (handle->connection->err)
        {
            redisFree(handle->connection);
            free(handle);
            return NULL;
        }

       if (redis_select(handle, db))
       {
           redisFree(handle->connection);
           free(handle);
           return NULL;
       }
    }

    return handle;
}

int redis_enqueue(struct kv_store* handle, uint64_t sector_num,
                  const uint8_t* data, size_t len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "SETEX %"PRIu64" %d %b",
                                                                &sector_num,
                                                                300,
                                                                data, len);
    return check_redis_return(handle->connection, reply);
}

/* defaults to 5 minutes timeout */
void redis_enqueue_pipelined(struct kv_store* handle, uint64_t sector_num,
                            const uint8_t* data, size_t len)
{
    redisAppendCommand(handle->connection, "SETEX %"PRIu64" %d %b",
                                                                   sector_num,
                                                                   300,
                                                                   data, len);
    handle->outstanding_pipelined_cmds++;
    if (handle->outstanding_pipelined_cmds >= 1000)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
}

int redis_publish(struct kv_store* handle, char* channel, uint8_t* data,
                  size_t len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "PUBLISH %s %b", channel,
                                                              data, len);
    return check_redis_return(handle->connection, reply);
}

int redis_dequeue(struct kv_store* handle, uint64_t sector_num, uint8_t* data,
                  size_t* len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "GET %"PRIu64, &sector_num);
    if (reply->type == REDIS_REPLY_STRING &&
        reply->len > 0 &&
        reply->len <= *len)
    {
        memcpy(data, reply->str, reply->len);
        *len = reply->len;
    }
    else
    {
        *len = 0;
    }

    return check_redis_return(handle->connection, reply);
}

int redis_hash_set(struct kv_store* handle, char* keyspace, uint64_t id, char* field,
                   uint8_t* data, size_t len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "HSET %s:%"PRIu64" %s %b", keyspace,
                                                                       id,
                                                                       field,
                                                                       data,
                                                                       len);
    return check_redis_return(handle->connection, reply);
}

int redis_hash_get(struct kv_store* handle, char* keyspace, uint64_t id, char* field,
                   uint8_t* data, size_t* len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, "HGET %s:%"PRIu64" %s", keyspace,
                                                                    id, field);
    if (reply->type == REDIS_REPLY_STRING &&
        reply->len > 0 &&
        reply->len <= *len)
    {
        memcpy(data, reply->str, reply->len);
        *len = reply->len;
    }
    else
    {
        *len = 0;
    }

    return check_redis_return(handle->connection, reply);
}

int redis_sector_lookup(struct kv_store* handle, uint64_t id, char* path,
                        size_t* len)
{
    redisReply* reply;
    unsigned long long inode = 0;
    reply = redisCommand(handle->connection, "HGET sector:%"PRIu64" inode", id);
    if (reply->type == REDIS_REPLY_INTEGER)
        inode = reply->integer;

    if (check_redis_return(handle->connection, reply))
        return 1;

    reply = redisCommand(handle->connection, "HGET inode:%llu path", reply->integer);

    if (reply->type == REDIS_REPLY_STRING &&
        reply->len > 0 &&
        reply->len <= *len)
    {
        memcpy(path, reply->str, reply->len);
        *len = reply->len;
    }
    else
    {
        *len = 0;
    }

    return check_redis_return(handle->connection, reply);
}

int redis_add_sector_map(struct kv_store*handle, uint64_t id,
                         uint64_t inode)
{
    redisReply* reply;
    reply = redisCommand(handle->connection,
                         "HSET sector:%"PRIu64" inode %"PRIu64, id, inode);
    return check_redis_return(handle->connection, reply);
}

void redis_shutdown(struct kv_store* handle)
{
    if (handle)
    {
        redisCommand(handle->connection, "FLUSHALL");
        if (handle->connection)
        {
            redisFree(handle->connection);
        }
        free(handle);
    }
}
