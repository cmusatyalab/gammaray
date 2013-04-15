/*****************************************************************************
 * qemu_common.h                                                             *
 *                                                                           *
 * This file contains function implementations for parsing binary data from  *
 * QEMU.                                                                     *
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
#include <stdlib.h>

#include "qemu_common.h"

#include "bson.h"

int qemu_load_md_filter(FILE* index, struct bitarray** bits)
{
    struct bson_kv value1, value2;
    struct bson_info* bson = bson_init();

    while (bson_readf(bson, index) == 1)
    {
        if (bson_deserialize(bson, &value1, &value2) != 1)
            break;
        
        if (strcmp(value1.key, "type") != 0)
        {
            fprintf_light_red(stderr, "Document missing 'type' field.\n");
            break;
        }
       
        if (strcmp(value1.data, "metadata_filter") == 0)
        {
            fprintf_light_yellow(stdout, "-- Deserializing a bitarray record "
                                         "--\n");
            if (bson_deserialize(bson, &value1, &value2) != 1)
                return EXIT_FAILURE;

            if (strcmp(value1.key, "bitarray") == 0)
            {
                *bits = bitarray_init_data((uint8_t*) value1.data,
                                           value1.size);
                return EXIT_SUCCESS;
            }
            else
            {
                fprintf_light_red(stderr, "Unexpected field in MD record.\n");
                break;
            }
        }
    }
    
    return EXIT_FAILURE;
}

void qemu_parse_header(uint8_t* event_stream, struct qemu_bdrv_write* write)
{
    write->header = *((struct qemu_bdrv_write_header*) event_stream);
}
