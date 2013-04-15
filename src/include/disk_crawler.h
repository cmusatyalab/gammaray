/*****************************************************************************
 * disk_crawler.h                                                            *
 *                                                                           *
 * Contains standardized interfaces for crawling individual file systems.    *
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
#ifndef __GAMMARAY_DISK_CRAWLER_H
#define __GAMMARAY_DISK_CRAWLER_H

struct fs
{
    uint64_t pte;
    uint64_t pt_off;
    void* cache;
    void* fs_info;
    struct bitarray* bits;
};

struct fs_crawler
{
   int (*probe) (FILE* disk, int pte, uint64_t pt_offset, struct fs* fs_super);
   int (*serialize_fs_bootstrap) (struct fs* fs_super, FILE* serializef);
   int (*serialize_fs_metadata) (FILE* disk, struct fs* fs_super,
                                 FILE* serializef);
   int (*serialize_fs_tree) (FILE* disk, struct fs* fs_super,
                             FILE* serializef);
   int (*serialize_metadata_bitarray) (struct fs* fs_super, FILE* serializef);
};

#endif
