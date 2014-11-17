/*****************************************************************************
 * bson_printer.c                                                            *
 *                                                                           *
 * This file implements a BSON tool that prints all BSON documents in a file.*
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013-2014 Carnegie Mellon University                          *
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
#include <sys/types.h>
#include <sys/stat.h>



#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>



#include "bson.h"
#include "color.h"
#include "util.h"

int main(int argc, char* argv[])
{
    int f;
    struct bson_info* bson;
    int ret;

    fprintf_blue(stdout, "BSON Printer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: %s <BSON file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing BSON File: %s\n", argv[1]);

    f = open(argv[1], O_RDONLY);

    if (f < 0)
    {
        fprintf_light_red(stderr, "Error opening BSON file.\n");
        return EXIT_FAILURE;
    }

    bson = bson_init();

    while ((ret = bson_readf(bson, f)) == 1)
        bson_print(stdout, bson);
    
    bson_cleanup(bson);
    check_syscall(close(f));

    return EXIT_SUCCESS;
}
