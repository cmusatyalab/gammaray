/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Push asynchronously all writes into a Redis queue.               * 
 *                                                                           *
 *****************************************************************************/

#include "color.h"

#include "redis_queue.h"
#include "qemu_common.h"

#include <event2/event.h>

#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct async_data 
{
    struct kv_store* handle;
    struct event_base* base; 
    struct event* event;
};

uint64_t diff_time(struct timeval start, struct timeval end)
{
    time_t delta_seconds = end.tv_sec - start.tv_sec;
    suseconds_t delta_micro = end.tv_usec - start.tv_usec;
    uint64_t micros = delta_seconds * 1000000 + delta_micro;
    return micros;
}

void read_qemu_write(evutil_socket_t fd, short what, void* data);

void schedule_read_event(evutil_socket_t fd, struct async_data* async)
{
    struct event *read_stream;
    read_stream = event_new(async->base, fd, EV_READ, read_qemu_write,
                            async); 

    if (async->event)
        event_free(async->event);

    async->event = read_stream;
    event_add(read_stream, NULL);
}

void read_qemu_write(evutil_socket_t fd, short what, void* data)
{
    struct timeval start, end;
    uint8_t buf[QEMU_HEADER_SIZE];
    int64_t total = 0, read_ret = 0;
    struct qemu_bdrv_write write;
    size_t len = QEMU_HEADER_SIZE;
    struct async_data* async = (struct async_data*) data;

    fprintf_light_blue(stdout, "read_qemu_write handler called.\n");
    
    gettimeofday(&start, NULL);
    if (what != EV_READ)
    {
        fprintf_light_red(stderr, "Event on fd NOT EV_READ!\n");
        redis_initiate_shutdown(async->handle);
        return;
    }

    read_ret = read(fd, buf, QEMU_HEADER_SIZE);
    total = read_ret;
    fprintf_light_red(stdout, "read: %"PRId64"\n", read_ret);

    while (read_ret > 0 && total < QEMU_HEADER_SIZE)
    {
        read_ret = read(fd, &buf[total], QEMU_HEADER_SIZE - total);
        total += read_ret;
    }

    /* check for EOF */
    if (read_ret == 0)
    {
        fprintf_light_red(stderr, "Total read: %"PRId64".\n", total);
        fprintf_light_red(stderr, "Reading from stream failed, assuming "
                                  "teardown.\n");
        close(fd);
        redis_initiate_shutdown(async->handle);
        return;
    }

    if (read_ret < 0)
    {
        fprintf_light_red(stderr, "Unknown fatal error occurred, 0 bytes"
                                   "read from stream.\n");
        redis_initiate_shutdown(async->handle);
        return;
    }

    qemu_parse_header(buf, &write);
    len = write.header.nb_sectors * SECTOR_SIZE + QEMU_HEADER_SIZE;
    fprintf_light_yellow(stdout, "Getting write of sectors %d\n", write.header.nb_sectors);
    fprintf_light_yellow(stdout, "Getting write of len %zu\n", len);
    write.data = (uint8_t*) malloc(len);

    if (write.data == NULL)
    {
        fprintf_light_red(stderr, "malloc() failed, assuming OOM.\n");
        fprintf_light_red(stderr, "tried allocating: %d bytes\n",
                                  write.header.nb_sectors*SECTOR_SIZE);
        redis_initiate_shutdown(async->handle);
        return;
    }

    memcpy(write.data, buf, QEMU_HEADER_SIZE);
    read_ret  = read(fd, (uint8_t*) &(write.data[QEMU_HEADER_SIZE]),
                     write.header.nb_sectors*SECTOR_SIZE);
    total = read_ret;

    while (read_ret > 0 && total < write.header.nb_sectors*SECTOR_SIZE)
    {
        read_ret  = read(fd, (uint8_t*) &write.data[total],
                         write.header.nb_sectors*SECTOR_SIZE - total);
        total += read_ret;
    }

    if (read_ret <= 0)
    {
        fprintf_light_red(stderr, "Stream ended while reading sector "
                                  "data.\n");
        redis_initiate_shutdown(async->handle);
        return;
    }

    fprintf_light_cyan(stdout, "async enqueueing --> we got full write.\n");
    /* the mountain of things i still regret ! */
    redis_async_write_enqueue(async->handle, write.data, len);

    schedule_read_event(fd, async);
    gettimeofday(&end, NULL);
    fprintf(stderr, "read_qemu_write call finished in %"PRIu64
                    " microseconds [%zu bytes]\n", diff_time(start, end),
                    write.header.nb_sectors*SECTOR_SIZE);
}

/* main thread of execution */
int main(int argc, char* args[])
{
    int fd;
    char* db, *stream;
    struct event_config *cfg = event_config_new();
    event_config_avoid_method(cfg, "epoll");
    struct event_base *base = event_base_new_with_config(cfg);
    struct async_data async;

    signal(SIGPIPE, SIG_IGN);

    fprintf_blue(stdout, "Async Qemu Queue Pusher -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    redis_print_version();

    if (argc < 3)
    {
        fprintf_light_red(stderr, "Usage: %s <stream file>"
                                  " <redis db num>\n", args[0]);
        return EXIT_FAILURE;
    }

    stream = args[1];
    db = args[2];

    if (base == NULL)
    {
        fprintf_light_red(stderr, "libevent handle is NULL.\n");
        return EXIT_FAILURE;
    }

    /* ----------------- hiredis ----------------- */
    struct kv_store* handle = redis_init(db, true, base);
    if (handle == NULL)
    {
        fprintf_light_red(stderr, "Failed getting Redis context "
                                  "(connection failure?).\n");
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Attaching to stream: %s\n\n", stream);

    if (strcmp(stream, "-") != 0)
    {
        fd = open(stream, O_RDONLY);
    }
    else
    {
        fd = STDIN_FILENO;
    }
    
    if (fd == -1)
    {
        fprintf_light_red(stderr, "Error opening stream file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);

    async.handle = handle;
    async.base = base;
    async.event = NULL;

    schedule_read_event(fd, &async);
    event_base_dispatch(base);
    
    fprintf_light_cyan(stdout, "Finised libevent event dispatch loop.\n");

    event_base_free(base);
    event_free(async.event);
    event_config_free(cfg);

    return EXIT_SUCCESS;
}
