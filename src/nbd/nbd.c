/*****************************************************************************
 * nbd.c                                                                     *
 *                                                                           *
 * This file contains an implementation of a libevent-based                  *
 * Network Block Device (NBD) protocol server.                               *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013 Carnegie Mellon University                               *
 *                                                                           *
 *   Licensed under the Apache License, Version 2.0 (the "License");         *
 *   you may not use this file except in compliance with the License.        *
 *   You may obtain a copy of the License at                                 *
 *                                                                           *
 *       http://www.apache.org/licenses/LICENSE-2.0                          *
 *                                                                           *
 *   Unless required by applicable law or agreed to in writing, software     *
 *   distributed under the License is distributed on an "AS IS" BASIS,       *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
 *   See the License for the specific language governing permissions and     *
 *   limitations under the License.                                          *
 *****************************************************************************/
#define _FILE_OFFSET_BITS 64

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "nbd.h"

#define GAMMARAY_NBD_MAGIC "NBDMAGIC"
#define GAMMARAY_NBD_SERVICE "nbd"

#define GAMMARAY_NBD_OLD_PROTOCOL 0x00420281861253LL
#define GAMMARAY_NBD_NEW_PROTOCOL 0x49484156454F5054LL

enum NBD_CMD
{
    NBD_CMD_READ            = 0x00,
    NBD_CMD_WRITE           = 0x01,
    NBD_CMD_DISC            = 0x02,
    NBD_CMD_FLUSH           = 0x03,
    NBD_CMD_TRIM            = 0x04
};

enum NBD_EXPORT_FLAG
{
    NBD_FLAG_HAS_FLAGS      = 0x01,
    NBD_FLAG_READ_ONLY      = 0x02,
    NBD_FLAG_SEND_FLUSH     = 0x04,
    NBD_FLAG_SEND_FUA       = 0x08,
    NBD_FLAG_ROTATIONAL     = 0x10,
    NBD_FLAG_SEND_TRIM      = 0x20
};

enum NBD_GLOBAL_FLAG
{
    NBD_FLAG_FIXED_NEWSTYLE = 0x01
};

enum NBD_OPT_TYPE
{
    NBD_OPT_EXPORT_NAME     = 0x01,
    NBD_OPT_ABORT           = 0x02,
    NBD_OPT_LIST            = 0x03
};

enum NBD_REP_TYPE
{
    NBD_REP_ACK             = 0x01,
    NBD_REP_SERVER          = 0x02,
    NBD_REP_ERR_UNSUP       = 0x80000001,
    NBD_REP_ERR_POLICY      = 0x80000002,
    NBD_REP_ERR_INVALID     = 0x80000003,
    NBD_REP_ERR_PLATFORM    = 0x080000004
};

struct nbd_old_handshake
{
    uint64_t magic;
    uint64_t protocol;
    uint64_t size;
    uint32_t flags;
    uint8_t pad[124];
} __attribute__((packed));

struct nbd_new_handshake
{
    uint64_t magic;
    uint64_t protocol;
    uint16_t global_flags;
} __attribute__((packed));

struct nbd_new_handshake_finish
{
    uint64_t size;
    uint16_t export_flags;
    uint8_t pad[124];
} __attribute__((packed));

struct nbd_req_header
{
    uint32_t magic;
    uint16_t type;
    uint16_t flags;
    uint64_t handle;
    uint64_t offset;
    uint64_t length;
} __attribute__((packed));

struct nbd_res_header
{
    uint32_t magic;
    uint32_t error;
    uint32_t handle;
} __attribute__((packed));

struct nbd_handle
{
    int fd;
    uint64_t fsize;
    uint64_t handle;
    char* export_name;
    struct event_base* eb;
    struct evconnlistener* conn;
};

/* private helper callbacks */
static void nbd_echo(struct bufferevent* bev, void* handle)
{
    struct evbuffer* in = bufferevent_get_input(bev);
    struct evbuffer* out = bufferevent_get_output(bev);

    evbuffer_add_buffer(out, in);
}

static void nbd_event_echo(struct bufferevent* bev, short events, void* handle)
{
    if (events & BEV_EVENT_ERROR)
        return;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
        bufferevent_free(bev);
}

static void nbd_new_conn(struct evconnlistener *conn, evutil_socket_t sock,
                         struct sockaddr *addr, int len, void *ptr)
{
    struct event_base* eb = evconnlistener_get_base(conn);
    struct bufferevent* bev = bufferevent_socket_new(eb, sock,
                                                     BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(bev, &nbd_echo, NULL, &nbd_event_echo, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

static void nbd_event_error(struct evconnlistener* conn, void* ptr)
{
    struct event_base* eb = evconnlistener_get_base(conn);
    event_base_loopexit(eb, NULL);
}

void nbd_run_loop(struct nbd_handle* handle)
{
    event_base_dispatch(handle->eb);
}

/* public library methods */
struct nbd_handle* nbd_init_file(char* export_name, char* fname,
                                 char* nodename, char* port)
{
    int fd = 0;
    struct stat st_buf;
    struct addrinfo hints;
    struct addrinfo* server = NULL;
    evutil_socket_t socket = 0;
    struct event_base* eb = NULL;
    struct nbd_handle* ret = NULL;
    struct evconnlistener* conn = NULL;

    /* sanity check */
    if (export_name == NULL || fname == NULL || port == NULL)
        return NULL;

    /* check and open file */
    memset(&st_buf, 0, sizeof(struct stat));

    if (stat(fname, &st_buf))
        return NULL;

    if ((fd = open(fname, O_RDWR)) == -1)
        return NULL;

    /* setup network socket */
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(nodename, port, &hints, &server))
    {
        if (server)
            freeaddrinfo(server);
        return NULL;
    }

    /* initialize libevent */
    if ((eb = event_base_new()) == NULL)
    {
        freeaddrinfo(server);
        close(fd);
        return NULL;
    }

    /* initialize this NBD module */
    if ((ret = (struct nbd_handle*) malloc(sizeof(struct nbd_handle))) == NULL)
    {
        freeaddrinfo(server);
        close(fd);
        event_base_free(eb);
        return NULL;
    }

    /* setup network connection */
    if ((conn = evconnlistener_new_bind(eb, &nbd_new_conn, ret,
                                        LEV_OPT_CLOSE_ON_FREE |
                                        LEV_OPT_REUSEABLE, -1,
                                        server->ai_addr,
                                        server->ai_addrlen)) == NULL)
    {
        freeaddrinfo(server);
        close(fd);
        event_base_free(eb);
        free(ret);
        return NULL;
    }

    evconnlistener_set_error_cb(conn, nbd_event_error);

    ret->fd = fd;
    ret->fsize = st_buf.st_size;
    ret->export_name = export_name;
    ret->eb = eb;
    ret->conn = conn;

    freeaddrinfo(server);

    return ret;
}

void nbd_run(struct nbd_handle* handle)
{
    event_base_dispatch(handle->eb);
}

void nbd_shutdown(struct nbd_handle* handle)
{
    if (handle == NULL)
        return;

    if (handle->fd)
        close(handle->fd);

    if (handle->eb)
        event_base_free(handle->eb);
}
