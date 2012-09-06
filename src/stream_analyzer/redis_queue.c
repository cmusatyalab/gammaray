#include "redis_queue.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define REDIS_DEFAULT_TIMEOUT 300 /* seconds; 5 minute default */

#define REDIS_DATA_INSERT "SET sector:%"PRIu64" "\
                          "start:%"PRIu64\
                          "end:%"PRIu64\
                          "inode:%"PRIu64

#define REDIS_ENQUEUE_WRITE "SETEX sector:%"PRIu64" %d %b"
#define REDIS_DEQUEUE_WRITE "GET sector:%"PRIu64
#define REDIS_DEL_WRITE "DEL sector:%"PRIu64

#define REDIS_PUBLISH "PUBLISH %s %b"

#define REDIS_FCOUNTER "HINCR fcounter"
#define REDIS_FCOUNTER_SET "SET fcounter %"PRIu64

/***** Helper Functions, not exposed *****/
struct kv_store
{
    redisContext* connection;
    uint64_t outstanding_pipelined_cmds;
};

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

int redis_enqueue_pipelined(struct kv_store* handle, uint64_t sector_num,
                            const uint8_t* data, size_t len)
{
    redisAppendCommand(handle->connection, REDIS_ENQUEUE_WRITE,
                                           sector_num,
                                           REDIS_DEFAULT_TIMEOUT,
                                           data, len);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= 1000)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_publish(struct kv_store* handle, char* channel, uint8_t* data,
                  size_t len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, REDIS_PUBLISH, channel, data,
                                                                     len);
    return check_redis_return(handle->connection, reply);
}

int redis_dequeue(struct kv_store* handle, uint64_t sector_num, uint8_t* data,
                  size_t* len)
{
    redisReply* reply;
    reply = redisCommand(handle->connection, REDIS_DEQUEUE_WRITE, sector_num);
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

    reply = redisCommand(handle->connection, REDIS_DEL_WRITE, sector_num);

    return check_redis_return(handle->connection, reply);
}

int redis_reverse_pointer_set(struct kv_store* handle, const char* fmt,
                              uint64_t src, uint64_t dst)
{
    redisAppendCommand(handle->connection, fmt,
                                           src,
                                           dst);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= 1000)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_hash_field_set(struct kv_store* handle, const char* fmt,
                         uint64_t src, char* field, uint8_t* data, size_t len)
{
    redisAppendCommand(handle->connection, fmt,
                                           src,
                                           field,
                                           data,
                                           len);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= 1000)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_hash_field_get(struct kv_store* handle, const char* fmt,
                         uint64_t src, char* field, uint8_t* data, size_t* len)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, fmt, src, field);
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

int redis_sector_lookup(struct kv_store* handle, uint64_t src,
                        uint8_t* data, size_t* len)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_DEQUEUE_WRITE, src);
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

int redis_reverse_file_data_pointer_set(struct kv_store* handle,
                                        uint64_t src, uint64_t start,
                                        uint64_t end, uint64_t dst)
{
    redisAppendCommand(handle->connection, REDIS_DATA_INSERT,
                                           src,
                                           start,
                                           end,
                                           dst);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= 1000)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_get_fcounter(struct kv_store* handle, uint64_t* counter)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_FCOUNTER);

    if (reply->type == REDIS_REPLY_INTEGER)
    {
        *counter = reply->integer;
    }

    return check_redis_return(handle->connection, reply);
}

int redis_set_fcounter(struct kv_store* handle, uint64_t counter)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_FCOUNTER_SET, counter);

    return check_redis_return(handle->connection, reply);
}

int redis_list_get(struct kv_store* handle, char* fmt, uint64_t src,
                   uint8_t** result[], size_t* len)
{
    uint64_t i;
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, fmt, src);

    if (reply->type == REDIS_REPLY_ARRAY)
    {
        *len = reply->elements;
        *result = malloc(sizeof(uint8_t*) * (*len));

        for (i = 0; i < *len; i++)
        {
            if (reply->element[i]->type != REDIS_REPLY_STRING)
            {
                check_redis_return(handle->connection, reply);
                free(*result);
                *result = NULL;
                return EXIT_FAILURE;
            }

            (*result)[i] = (uint8_t*) malloc(reply->len + 1);

            memcpy((*result)[i], reply->element[i]->str,
                   (size_t) reply->element[i]->len);

            (*result)[i][reply->element[i]->len] = 0;
        }
    }

    return check_redis_return(handle->connection, reply);
}


void redis_free_list(uint8_t* list[], size_t len)
{
    size_t i;

    if (list)
    {
        for (i = 0; i < len; i++)
        {
            if (list[i])
                free(list[i]);
        }
        free(list);
    }
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
