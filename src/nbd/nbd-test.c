/*****************************************************************************
 * nbd-test.c                                                                *
 *                                                                           *
 * This file contains a NBD test server based on a host file.                *
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
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "color.h"
#include "nbd.h"

#define USAGE "%s <backing file> <export name>\n"

struct nbd_handle
{
    int fd;
    uint64_t fsize;
    uint64_t handle;
    char* export_name;
    struct event_base* eb;
    struct evconnlistener* conn;
};

int main(int argc, char* argv[])
{
    struct nbd_handle* handle;
   
    if (argc < 3)
    {
        fprintf_light_red(stderr, USAGE, argv[0]);
        exit(EXIT_FAILURE);
    }

    fprintf_blue(stdout, "nbd-test program by: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");
    fprintf_white(stdout, "backing file: %s\n", argv[1]);
    fprintf_white(stdout, "export name: %s\n", argv[2]);

    handle = nbd_init_file(argv[2], argv[1],
                           "0.0.0.0", "10809");

    assert(handle != NULL);
    assert(handle->fd != 0);
    assert(strncmp(argv[2], handle->export_name, strlen(argv[2])) == 0);
    assert(handle->eb != NULL);
    assert(handle->conn != NULL);
    assert(handle->fsize != 0);
    
    nbd_run_loop(handle);
    nbd_shutdown(handle);

    fprintf_light_green(stdout, "-- Passed all tests --\n");
    return EXIT_SUCCESS;
}
