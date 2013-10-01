/*****************************************************************************
 * nbd.h                                                                     *
 *                                                                           *
 * This file contains function prototypes that can implement a libevent-based*
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
#ifndef __GAMMARAY_NBD_H
#define __GAMMARAY_NBD_H

#include <stdbool.h>

#define GAMMARAY_NBD_PORT 10809

struct nbd_handle;
struct nbd_req_header;

struct nbd_handle* nbd_init_file(char* export_name, char* fname,
                                 char* nodename, char* port, bool old);
void nbd_shutdown(struct nbd_handle* handle);
int nbd_handle_read(struct nbd_handle* handle, struct nbd_req_header* hdr);
int nbd_handle_write(struct nbd_handle* handle, struct nbd_req_header* hdr);
int nbd_handle_disconnect(struct nbd_handle* handle,
                          struct nbd_req_header* hdr);
int nbd_handle_flush(struct nbd_handle* handle, struct nbd_req_header* hdr);
int nbd_handle_trim(struct nbd_handle* handle, struct nbd_req_header* hdr);
void nbd_run_loop(struct nbd_handle* handle);

#endif
