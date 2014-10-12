/*****************************************************************************
 * gpt.h                                                                     *
 *                                                                           *
 * This file contains function prototypes that can read and interpret a      *
 * Global Partition Table (gpt).                                             *
 *                                                                           *
 *                                                                           *
 *                                                                           *
 *   Authors: Brandon Amos <bamos@cs.cmu.edu>                                *
 *            Wolfgang Richter <wolf@cs.cmu.edu>                             *
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
#ifndef __GAMMARAY_DISK_CRAWLER_gpt_H
#define __GAMMARAY_DISK_CRAWLER_gpt_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "bitarray.h"
#include "gray-crawler.h"

struct disk_gpt
{
    // TODO
    uint8_t signature[8];
}__attribute__((packed));

int gpt_probe(FILE* disk, struct pt* pt);
void gpt_print(struct pt pt);
int gpt_serialize_pt(struct pt pt, struct bitarray* bits,
                     FILE* serializef);
int gpt_serialize_pte(struct pte pte, FILE* serializef);
bool gpt_get_next_partition(struct pt pt, struct pte* pte);
int gpt_cleanup_pt(struct pt pt);
int gpt_cleanup_pte(struct pte pte);
#endif

