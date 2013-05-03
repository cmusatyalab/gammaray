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
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <linux/falloc.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include "util.h"
#include "nbd.h"

#define GAMMARAY_NBD_MAGIC 0x4e42444d41474943LL
#define GAMMARAY_NBD_SERVICE "nbd"

#define GAMMARAY_NBD_OLD_PROTOCOL 0x00420281861253LL
#define GAMMARAY_NBD_NEW_PROTOCOL 0x49484156454F5054LL
#define GAMMARAY_NBD_REPLY_MAGIC  0x3e889045565a9LL

#define GAMMARAY_NBD_REQ_MAGIC 0x25609513
#define GAMMARAY_NBD_REP_MAGIC 0x67446698

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
    uint32_t type;
    uint64_t handle;
    uint64_t offset;
    uint32_t length;
} __attribute__((packed));

struct nbd_res_header
{
    uint32_t magic;
    uint32_t error;
    uint64_t handle;
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
    enum NBD_CLIENT_STATE state;
    struct nbd_handle* handle;
    evutil_socket_t socket;
    uint32_t toread;
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

bool __send_response(struct evbuffer* out, uint32_t error,
                     uint64_t handle, uint8_t* data, uint32_t len)
{
    struct nbd_res_header hdr = {
                                    .magic  = htobe32(GAMMARAY_NBD_REP_MAGIC),
                                    .error  = htobe32(error),
                                    .handle = htobe64(handle) 
                                };

    evbuffer_add(out, &hdr, sizeof(hdr));

    if (data && len)
        evbuffer_add(out, data, (size_t) len);

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
                case NBD_OPT_EXPORT_NAME:
                    name_len = be32toh(peek->len);

                    if (name_len != client->handle->name_len)
                        goto fail;

                    if (evbuffer_get_length(in) <
                        sizeof(struct nbd_opt_header) + name_len)
                        return true;

                    evbuffer_drain(in, sizeof(struct nbd_opt_header));
                    export_name = (char*) evbuffer_pullup(in, name_len);

                    if (export_name == NULL)
                        return true;

                    if (strncmp(export_name,
                                client->handle->export_name,
                                name_len) == 0)
                    {
                        __send_export_info(out, client->handle);
                        client->state = NBD_DATA_PUSHING;
                        evbuffer_drain(in, name_len);
                        return false;
                    }
                    else
                    {
                        client->state = NBD_DISCONNECTED;
                    }

                case NBD_OPT_ABORT:
                    goto fail;

                case NBD_OPT_LIST:
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

uint32_t __handle_read(struct nbd_req_header* req, struct nbd_client* client)
{
    off64_t offset;
    uint8_t* buf;
    ssize_t ret;
    size_t len;
    int fd;

    offset = be64toh(req->offset);
    len = be32toh(req->length);
    buf = realloc(client->buf, len);
    client->buf = buf;
    fd = client->handle->fd;

    assert(buf != NULL);

    if (lseek64(fd, offset, SEEK_SET) == (off_t) -1)
        return errno;

    while (len)
    {
        if ((ret = read(fd, buf, len)) == (ssize_t) -1)
            return errno;
        len -= ret;
    }

    return 0;
}

uint32_t __handle_write(struct nbd_req_header* req, struct nbd_client* client,
                        struct evbuffer* in)
{
    off64_t offset;
    uint8_t* buf;
    ssize_t ret;
    size_t len, pos = 0;
    int fd;

    offset = be64toh(req->offset);
    len = be32toh(req->length);
    buf = realloc(client->buf, len);
    client->buf = buf;
    fd = client->handle->fd;

    assert(in != NULL);
    assert(buf != NULL);

    if (evbuffer_get_length(in) < sizeof(struct nbd_req_header) + len)
        return -1;

    evbuffer_drain(in, sizeof(struct nbd_req_header));

    if (evbuffer_copyout(in, buf, len) < len)
        return -1;

    if (lseek64(fd, offset, SEEK_SET) == (off_t) -1)
        return errno;

    while (pos < len)
    {
        if ((ret = write(fd, &(buf[pos]), len)) == (ssize_t) -1)
            return errno;
        pos += ret;
    }

    return 0;
}

bool __check_request(struct evbuffer* in, struct evbuffer* out,
                     struct nbd_client* client)
{
    struct nbd_req_header* peek = NULL;
    struct nbd_req_header req;
    uint32_t err = 0;
    uint64_t handle = 0;
    void* test = NULL;
    peek = (struct nbd_req_header*)
           evbuffer_pullup(in, sizeof(struct nbd_req_header));

    if (peek)
    {
        memcpy(&req, peek, sizeof(struct nbd_req_header));
        
        if (be32toh(req.magic) == GAMMARAY_NBD_REQ_MAGIC)
        {
            handle = be64toh(req.handle);

            switch(be32toh(req.type))
            {
                case NBD_CMD_READ:
                    err = __handle_read(peek, client);
                    if (err == -1)
                        return true;
                    evbuffer_drain(in, sizeof(struct nbd_req_header));
                    __send_response(out, err, handle,
                                    client->buf, be32toh(req.length));
                    return false;
                case NBD_CMD_WRITE:
                    err = __handle_write(peek, client, in);
                    if (err == -1)
                        return true;
                    evbuffer_drain(in, be32toh(req.length));
                    __send_response(out, err, handle, NULL, 0);
                    return false;
                case NBD_CMD_DISC:
                    fprintf(stderr, "got disconnect.\n");
                    client->state = NBD_DISCONNECTED;
                    evbuffer_drain(in, sizeof(struct nbd_req_header));
                    evutil_closesocket(client->socket);
                    return false;
                case NBD_CMD_FLUSH:
                    fprintf(stderr, "got flush.\n");
                    evbuffer_drain(in, sizeof(struct nbd_req_header));
                    if (fsync(client->handle->fd))
                        __send_response(out, errno, handle, NULL, 0);
                    else
                        __send_response(out, 0, handle, NULL, 0);
                    return false;
                case NBD_CMD_TRIM:
                    fprintf(stderr, "got trim.\n");
                    evbuffer_drain(in, sizeof(struct nbd_req_header));
                    if (fallocate(client->handle->fd,
                                  FALLOC_FL_PUNCH_HOLE |
                                  FALLOC_FL_KEEP_SIZE,
                                  be64toh(req.offset),
                                  be32toh(req.length)))
                        __send_response(out, errno, handle, NULL, 0);
                    else
                        __send_response(out, 0, handle, NULL, 0);
                    return false;
                default:
                    test = evbuffer_pullup(in, sizeof(struct nbd_req_header) +
                                               be32toh(req.length));
                    if (test)
                        evbuffer_drain(in, sizeof(struct nbd_req_header) +
                                       be32toh(req.length));
                    fprintf(stderr, "unknown command!\n");
            };
        }
    }

    return true;
}

/* private helper callbacks */
static void nbd_client_handler(struct bufferevent* bev, void* client)
{
    struct evbuffer* in  = bufferevent_get_input(bev);
    struct evbuffer* out = bufferevent_get_output(bev);
    int counter = 10;

    while (evbuffer_get_length(in) && counter-- > 0)
    {
        switch (((struct nbd_client*) client)->state)
        {
            case NBD_HANDSHAKE_SENT:
               if (__check_zero_handshake(in, client))
                   break;
            case NBD_ZERO_RECEIVED:
               if (__check_opt_header(in, out, client))
                  break; 
            case NBD_DATA_PUSHING:
               if (__check_request(in, out, client))
                   return;
               break;
            case NBD_DISCONNECTED:
                evutil_closesocket(((struct nbd_client*) client)->socket);
            default:
               return;
        };
    }
}

static void nbd_ev_handler(struct bufferevent* bev, short events, void* client)
{
    if (events & BEV_EVENT_ERROR)
        return;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        bufferevent_free(bev);
        if (((struct nbd_client*) client)->buf)
            free(((struct nbd_client*) client)->buf);
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
    client->buf = NULL;

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
