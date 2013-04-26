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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <netdb.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "nbd.h"

#define GAMMARAY_NBD_MAGIC 0x4e42444d41474943LL
#define GAMMARAY_NBD_SERVICE "nbd"

#define GAMMARAY_NBD_OLD_PROTOCOL 0x00420281861253LL
#define GAMMARAY_NBD_NEW_PROTOCOL 0x49484156454F5054LL
#define GAMMARAY_NBD_REPLY_MAGIC  0x3e889045565a9LL

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

enum NBD_CLIENT_STATE
{
    NBD_HANDSHAKE_SENT,
    NBD_ZERO_RECEIVED,
    NBD_OPTION_SETTING,
    NBD_DATA_PUSHING,
    NBD_DISCONNECTED
};

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

struct nbd_opt_header
{
    uint64_t magic;
    uint32_t option;
    uint32_t len;
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

struct nbd_res_opt_header
{
    uint64_t magic;
    uint32_t option;
    uint32_t type;
    uint32_t len;
} __attribute__((packed));

struct nbd_handle
{
    int fd;
    uint64_t size;
    uint64_t handle;
    char* export_name;
    uint32_t name_len;
    struct event_base* eb;
    struct evconnlistener* conn;
};

struct nbd_client
{
    struct nbd_handle* handle;
    evutil_socket_t socket;
    enum NBD_CLIENT_STATE state;
    uint8_t* buf;
};

bool __check_zero_handshake(struct evbuffer* in,
                            struct nbd_client* client)
{
    uint32_t* peek;
    peek = (uint32_t*) evbuffer_pullup(in, 4);

    if (peek && (*peek == 0))
    {
        evbuffer_drain(in, 4);
        client->state = NBD_ZERO_RECEIVED;
        return false;
    }

    return true;
}

bool __send_export_info(struct evbuffer* out, struct nbd_handle* handle)
{
    struct nbd_new_handshake_finish hdr = {
                                            .size = htobe64(handle->size),
                                            .export_flags =
                                                htobe16(NBD_FLAG_HAS_FLAGS |
                                                        NBD_FLAG_SEND_FLUSH |
                                                        NBD_FLAG_SEND_FUA |
                                                        NBD_FLAG_ROTATIONAL |
                                                        NBD_FLAG_SEND_TRIM),
                                            .pad = {0}
                                          };
    evbuffer_add(out, &hdr, sizeof(hdr));
    return true;
}

bool __send_unsupported_opt(struct evbuffer* out, uint32_t option)
{
    struct nbd_res_opt_header hdr = {
                                        .magic =
                                            htobe64(GAMMARAY_NBD_REPLY_MAGIC), 
                                        .option = option,
                                        .type = htobe32(NBD_REP_ERR_UNSUP),
                                        .len = 0
                                    };
    evbuffer_add(out, &hdr, sizeof(hdr));
    return true;
}

bool __check_opt_header(struct evbuffer* in, struct evbuffer* out,
                        struct nbd_client* client)
{
    struct nbd_opt_header* peek;
    char* export_name;
    uint32_t name_len;
    peek = (struct nbd_opt_header*)
           evbuffer_pullup(in, sizeof(struct nbd_opt_header));

    if (peek)
    {
        if (be64toh(peek->magic) == GAMMARAY_NBD_NEW_PROTOCOL)
        {
            switch (be32toh(peek->option))
            {
                NBD_OPT_EXPORT_NAME:
                    name_len = be32toh(peek->len);

                    if (name_len != client->handle->name_len)
                        goto fail;

                    export_name = evbuffer_pullup(in, name_len);

                    if (export_name == NULL)
                        return true;
                    
                    if (strncmp(export_name,
                                          client->handle->export_name,
                                          name_len) == 0)
                    {
                        __send_export_info(out, client->handle);
                        client->state = NBD_DATA_PUSHING;
                        return false;
                    }

                NBD_OPT_ABORT:
                    goto fail;

                NBD_OPT_LIST:
                default:
                    __send_unsupported_opt(out, peek->option);
                    return true;
            };
        }
fail:
        evutil_closesocket(client->socket);
        return true;
    }

    return true;
}

/* private helper callbacks */
static void nbd_client_handler(struct bufferevent* bev, void* client)
{
    struct evbuffer* in  = bufferevent_get_input(bev);
    struct evbuffer* out = bufferevent_get_output(bev);

    switch (((struct nbd_client*) client)->state)
    {
        case NBD_HANDSHAKE_SENT:
           if (__check_zero_handshake(in, client))
               break;
        case NBD_ZERO_RECEIVED:
           if (__check_opt_header(in, out, client))
              break; 
        case NBD_DATA_PUSHING:
        case NBD_DISCONNECTED:
        default:
            break;
    };
}

static void nbd_ev_handler(struct bufferevent* bev, short events, void* client)
{
    if (events & BEV_EVENT_ERROR)
        return;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        bufferevent_free(bev);
        free(client);
    }
}

static void nbd_new_conn(struct evconnlistener *conn, evutil_socket_t sock,
                         struct sockaddr *addr, int len, void * handle)
{
    struct event_base* eb = evconnlistener_get_base(conn);
    struct bufferevent* bev = bufferevent_socket_new(eb, sock,
                                                     BEV_OPT_CLOSE_ON_FREE);
    struct evbuffer* out = bufferevent_get_output(bev);
    struct nbd_new_handshake hdr = { .magic        =
                                            htobe64(GAMMARAY_NBD_MAGIC),
                                     .protocol     =
                                            htobe64(GAMMARAY_NBD_NEW_PROTOCOL),
                                     .global_flags =
                                            htobe16(NBD_FLAG_FIXED_NEWSTYLE)
                                   };
    struct nbd_client* client = (struct nbd_client*)
                                    malloc(sizeof(struct nbd_client));

    client->handle = handle;
    client->state = NBD_HANDSHAKE_SENT;
    client->socket = sock;

    bufferevent_setcb(bev, &nbd_client_handler, NULL, &nbd_ev_handler, client);
    evbuffer_add(out, &hdr, sizeof(hdr));
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
    ret->size = st_buf.st_size;
    ret->export_name = export_name;
    ret->name_len = strlen(export_name);
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
