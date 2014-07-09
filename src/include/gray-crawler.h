/*****************************************************************************
 * gray-crawler.h                                                            *
 *                                                                           *
 * Contains standardized interfaces for crawling individual file systems.    *
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
#ifndef __GAMMARAY_GRAY_CRAWLER_H
#define __GAMMARAY_GRAY_CRAWLER_H

#include <stdint.h>
#include <stdio.h>

#define GRAY_FS(NAME) { #NAME, NAME ## _probe, NAME ## _serialize, NAME ## \
_cleanup}

struct fs
{
    uint64_t pte;
    int64_t pt_off;
    uint8_t* icache;
    uint8_t* bcache;
    void* fs_info;
    struct bitarray* bits;
};

struct gray_fs_crawler
{
    char* fs_name;
    int (*probe) (FILE* disk, struct fs* fs);
    int (*serialize) (FILE* disk, struct fs* fs, FILE* serializef);
    int (*cleanup) (struct fs* fs);
};

#endif
