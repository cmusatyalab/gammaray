/*****************************************************************************
 * bitarray.h                                                                *
 *                                                                           *
 * This file contains prototypes for functions implementing an in-memory     *
 * bit array.                                                                *
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
#ifndef __GAMMARAY_BITARRAY_H
#define __GAMMARAY_BITARRAY_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

struct bitarray;

bool bitarray_get_bit(struct bitarray* bits, uint64_t bit);
void bitarray_set_bit(struct bitarray* bits, uint64_t bit);
void bitarray_unset_bit(struct bitarray* bits, uint64_t bit);
void bitarray_set_all(struct bitarray* bits);
void bitarray_unset_all(struct bitarray* bits);
void bitarray_print(struct bitarray* bits);
struct bitarray* bitarray_init(uint64_t len);
struct bitarray* bitarray_init_data(uint8_t* data, uint64_t len);
void bitarray_destroy(struct bitarray* bits);
uint64_t bitarray_get_array(struct bitarray* bits, uint8_t** array);
int bitarray_serialize(struct bitarray* bits, int serializef);

#endif
