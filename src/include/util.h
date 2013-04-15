/*****************************************************************************
 * util.h                                                                    *
 *                                                                           *
 * This file contains prototypes for miscellaneous widely-applicable utility *
 * functions, suitable for including in other C files within a project.      *
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
#ifndef __GAMMARAY_UTIL_UTIL_H
#define __GAMMARAY_UTIL_UTIL_H

#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>

int hexdump(uint8_t* buf, uint64_t len);

int pretty_print_bytes(uint64_t bytes, char* buf, uint64_t bufsize);
int pretty_print_microseconds(uint64_t micros, char* buf, uint64_t bufsize);

bool top_bit_set(uint8_t byte);
uint32_t highest_set_bit(uint32_t val);
uint64_t highest_set_bit64(uint64_t val);
int32_t sign_extend(uint32_t val, uint32_t bits);
int64_t sign_extend64(uint64_t val, uint64_t bits);

uint64_t diff_time(struct timeval start, struct timeval end);
#endif
