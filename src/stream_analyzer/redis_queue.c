#include "util.h"

#include "redis_queue.h"

#include "hiredis.h"

#define __USE_GNU
#include <pthread.h>
#undef __USE_GNU

#include <semaphore.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REDIS_DEFAULT_TIMEOUT 300 /* seconds; 5 minute */
#define REDIS_DEFAULT_FLUSH_TICK 5 /* seconds; 5 */
#define REDIS_DEFAULT_PIPELINED 16384 /* unitless; 16384 (4096*16384=64MB) */
#define REDIS_DEFAULT_BYTES 262144000 /* bytes; 250 MiB */


#define REDIS_SECTOR_GET "GET sector:%"PRIu64

#define REDIS_DATA_INSERT "SET sector:%"PRIu64" "\
                          "start:%"PRIu64":"\
                          "end:%"PRIu64":"\
                          "file:%"PRIu64

#define REDIS_ENQUEUE_WRITE "SETEX qsector:%"PRIu64" %d %b"
#define REDIS_DEQUEUE_WRITE "GET qsector:%"PRIu64
#define REDIS_DEL_WRITE "DEL qsector:%"PRIu64

#define REDIS_PUBLISH "PUBLISH %s %b"

#define REDIS_FCOUNTER "INCR fcounter"
#define REDIS_FCOUNTER_SET "SET fcounter %"PRIu64

/***** Helper Functions, not exposed *****/
struct thread_job
{
    struct kv_store* handle;
    uint64_t cmds_to_process;
};

struct kv_store
{
    redisContext* connection;
    uint64_t outstanding_pipelined_cmds;
    size_t outstanding_bytes;
    pthread_mutex_t flush_lock;
    pthread_mutex_t conn_lock;
    pthread_mutex_t cmd_lock;
    bool shutdown;
    sem_t thread_counter;
};

int check_redis_return(struct kv_store* handle, redisReply* reply)
{
    if (reply == NULL || ((int) reply) == REDIS_ERR)
    {
        switch(handle->connection->err)
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
    return check_redis_return(handle, reply);
}

int redis_flush_pipeline(struct kv_store* handle)
{
    redisReply* reply;

    while (handle->outstanding_pipelined_cmds)
    {
        redisGetReply(handle->connection, (void**) &reply);
        if(check_redis_return(handle, reply))
        {
            return EXIT_FAILURE;
        }
        handle->outstanding_pipelined_cmds--;
    }

    return EXIT_SUCCESS;
}

void* redis_flush_thread_pipeline(void* data)
{
    struct thread_job* job = (struct thread_job*) data;
    redisReply* reply;
    struct timeval start, end;
    pthread_mutex_lock(&(job->handle->flush_lock));
    gettimeofday(&start, NULL);

    while (job->cmds_to_process)
    {
        pthread_mutex_lock(&(job->handle->conn_lock));
        redisGetReply(job->handle->connection, (void**) &reply);
        if(check_redis_return(job->handle, reply))
        {
            fprintf(stderr, "ERROR FLUSHING\n");
            pthread_mutex_unlock(&(job->handle->flush_lock));
            assert(true);
        }
        pthread_mutex_unlock(&(job->handle->conn_lock));
        job->cmds_to_process--;
    }
    gettimeofday(&end, NULL);
    fprintf(stderr, "redis_flush_pipeline finished in %"PRIu64
                        " microseconds\n",
                        diff_time(start, end));
    sem_wait(&(job->handle->thread_counter));
    pthread_mutex_unlock(&(job->handle->flush_lock));
    free(job);

    return EXIT_SUCCESS;
}

void * redis_periodic_flusher(void* data)
{
    struct thread_job* job = NULL;

    while (!(((struct kv_store *) data)->shutdown))
    {
        fprintf(stderr, "PERIODIC FLUSHER RUNNING.\n");
        sleep(REDIS_DEFAULT_FLUSH_TICK);
        job = (struct thread_job*) malloc(sizeof(struct thread_job));
        job->handle = (struct kv_store*) data;

        pthread_mutex_lock(&(job->handle->cmd_lock));
        job->cmds_to_process = job->handle->outstanding_pipelined_cmds;
        job->handle->outstanding_pipelined_cmds = 0;
        pthread_mutex_unlock(&(job->handle->cmd_lock));

        sem_post(&(job->handle->thread_counter));

        redis_flush_thread_pipeline(job);
    }

    return EXIT_SUCCESS;
}

/***** Core API *****/
void redis_print_version()
{
    fprintf(stdout, "Current libhiredis version is %d.%d.%d\n", HIREDIS_MAJOR,
                                                                HIREDIS_MINOR,
                                                                HIREDIS_PATCH);
}

struct kv_store* redis_init(char* db, bool background_flush)
{
    struct timeval timeout = { 1, 500000 };
    struct kv_store* handle = (struct kv_store*)
                              malloc(sizeof(struct kv_store));
    pthread_t thread;

    if (handle)
    {
        handle->connection = redisConnectWithTimeout("127.0.0.1",
                                                     6379, timeout);
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

        handle->outstanding_pipelined_cmds = 0;
        handle->shutdown = false;
        pthread_mutex_init(&(handle->flush_lock), NULL);
        pthread_mutex_init(&(handle->conn_lock), NULL);
        pthread_mutex_init(&(handle->cmd_lock), NULL);
        sem_init(&(handle->thread_counter), 0, 0);

        if (background_flush)
            pthread_create(&thread, NULL, redis_periodic_flusher, handle);
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

    if (handle->outstanding_pipelined_cmds >= REDIS_DEFAULT_PIPELINED)
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
    return check_redis_return(handle, reply);
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

    return check_redis_return(handle, reply);
}

int redis_reverse_pointer_set(struct kv_store* handle, const char* fmt,
                              uint64_t src, uint64_t dst)
{
    redisAppendCommand(handle->connection, fmt,
                                           src,
                                           dst);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= REDIS_DEFAULT_PIPELINED)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_hash_field_set(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, const uint8_t* data, size_t len)
{
    redisAppendCommand(handle->connection, fmt,
                                           src,
                                           field,
                                           data,
                                           len);
    handle->outstanding_pipelined_cmds++;

    if (handle->outstanding_pipelined_cmds >= REDIS_DEFAULT_PIPELINED)
    {
        if (redis_flush_pipeline(handle))
        {
            assert(true);
        }
    }
    return EXIT_SUCCESS;
}

int redis_hash_field_get(struct kv_store* handle, const char* fmt,
                         uint64_t src, const char* field, uint8_t* data, size_t* len)
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

    return check_redis_return(handle, reply);
}

int redis_sector_lookup(struct kv_store* handle, uint64_t src,
                        uint8_t* data, size_t* len)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_SECTOR_GET, src);
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

    return check_redis_return(handle, reply);
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

    if (handle->outstanding_pipelined_cmds >= REDIS_DEFAULT_PIPELINED)
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

    return check_redis_return(handle, reply);
}

int redis_set_fcounter(struct kv_store* handle, uint64_t counter)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_FCOUNTER_SET, counter);

    return check_redis_return(handle, reply);
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

        if (*result == NULL)
            return EXIT_FAILURE;

        for (i = 0; i < *len; i++)
        {
            if (reply->element[i]->type != REDIS_REPLY_STRING)
            {
                check_redis_return(handle, reply);
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

    return check_redis_return(handle, reply);
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

int redis_async_write_enqueue(struct kv_store* handle, int64_t sector,
                                                       uint8_t* data,
                                                       size_t len)
{
    struct thread_job* job;
    pthread_t thread;
    pthread_mutex_lock(&(handle->conn_lock));
    redisAppendCommand(handle->connection, REDIS_ASYNC_QUEUE_PUSH,
                                           &sector,
                                           sizeof(sector));
    redisAppendCommand(handle->connection, REDIS_ASYNC_QUEUE_PUSH,
                                           data,
                                           len);
    pthread_mutex_unlock(&(handle->conn_lock));

    pthread_mutex_lock(&(handle->cmd_lock));

    handle->outstanding_pipelined_cmds++;
    handle->outstanding_bytes += sizeof(sector);
    handle->outstanding_pipelined_cmds++;
    handle->outstanding_bytes += len;

    if (handle->outstanding_pipelined_cmds >= REDIS_DEFAULT_PIPELINED ||
        handle->outstanding_bytes > REDIS_DEFAULT_BYTES)
    {
        job = (struct thread_job*) malloc(sizeof(struct thread_job));
        job->handle = handle;
        job->cmds_to_process = handle->outstanding_pipelined_cmds;
        handle->outstanding_pipelined_cmds = 0;
        pthread_mutex_unlock(&(handle->cmd_lock));
        sem_post(&(handle->thread_counter));
        if (pthread_create(&thread, NULL, redis_flush_thread_pipeline, job))
        {
            assert(true);
        }
        handle->outstanding_bytes = 0;
    }
    else
    {
        pthread_mutex_unlock(&(handle->cmd_lock));
    }

    return EXIT_SUCCESS;
}

int redis_async_write_dequeue(struct kv_store* handle,
                              struct qemu_bdrv_write* write)
{
    redisReply* reply;
    redis_flush_pipeline(handle);

    /* get sector number */
    reply = redisCommand(handle->connection, REDIS_ASYNC_QUEUE_POP);

    if (reply->type == REDIS_REPLY_ARRAY &&
        reply->elements == 2 &&
        reply->element[1]->type == REDIS_REPLY_STRING &&
        reply->element[1]->len == sizeof(write->header.sector_num))
    {
        memcpy((uint8_t*) &(write->header.sector_num),
               reply->element[1]->str, reply->element[1]->len);
    }
    else
    {
        fprintf(stdout, "Error len: %d\n", reply->element[1]->len);
        write->header.sector_num = -1;
        return EXIT_FAILURE;
    }

    check_redis_return(handle, reply);

    /* get sector number */
    reply = redisCommand(handle->connection, REDIS_ASYNC_QUEUE_POP);

    if (reply->type == REDIS_REPLY_ARRAY &&
        reply->elements == 2)
    {
        write->data = NULL;
        write->data = malloc(reply->element[1]->len);
        if (write->data)
        {
            memcpy(write->data, reply->element[1]->str,
                                reply->element[1]->len);
            write->header.nb_sectors = reply->element[1]->len / SECTOR_SIZE;
        }
        else
        {
            write->header.nb_sectors = 0;
            return EXIT_FAILURE;
        }
    }
    else
    {
        write->header.nb_sectors = 0;
        write->data = NULL;
        return EXIT_FAILURE;
    }

    return check_redis_return(handle, reply);
}

int redis_set_add(struct kv_store* handle, char* fmt, uint64_t id)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, fmt, id);

    return check_redis_return(handle, reply);
}

int redis_set_remove(struct kv_store* handle, char* fmt, uint64_t id,
                     uint64_t* result)
{
    redisReply* reply;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, fmt, id);

    if (reply->type == REDIS_REPLY_INTEGER)
    {
        *result = (uint64_t) reply->integer;
    }
    else
    {
        *result = 0;
    }

    return check_redis_return(handle, reply);
}

int redis_set_reset(struct kv_store* handle)
{
    redisReply* reply;
    redisReply* reply2;
    redis_flush_pipeline(handle);
    reply = redisCommand(handle->connection, REDIS_RESET_CREATED);
    reply2 = redisCommand(handle->connection, REDIS_RESET_DELETED);

    return check_redis_return(handle, reply) ||
           check_redis_return(handle, reply2);
}

void redis_shutdown(int exit_value, struct kv_store* handle)
{
    int outstanding = 0;

    if (handle)
    {
        /* wait for all threads */
        handle->shutdown = true;
        sem_getvalue(&(handle->thread_counter), &outstanding);
        while (outstanding != 0)
        {
            fprintf(stderr, "waiting for threads: %d\n", outstanding);
            sem_getvalue(&(handle->thread_counter), &outstanding);
            sleep(1);
        }

        redis_flush_pipeline(handle);

        if (handle->connection)
        {
            redisFree(handle->connection);
        }

        pthread_mutex_destroy(&(handle->flush_lock));
        pthread_mutex_destroy(&(handle->conn_lock));
        pthread_mutex_destroy(&(handle->cmd_lock));
        sem_destroy(&(handle->thread_counter));
        free(handle);
    }
}
