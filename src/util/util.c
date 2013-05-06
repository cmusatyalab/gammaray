/*****************************************************************************
 * util.c                                                                    *
 *                                                                           *
 * This file contains implementations for miscellaneous widely-applicable    *
 * utility functions.                                                        *
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
#include "util.h"
#include "color.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define KB 1024L
#define MB (KB*1024)
#define GB (MB*1024)
#define TB (GB*1024)

#define MILLIS 1000L
#define SECONDS (MILLIS*MILLIS)
#define MINUTES (SECONDS*60)
#define HOURS (MINUTES*60)
#define DAYS (HOURS*24)

bool top_bit_set(uint8_t byte)
{
    return 0x80 & byte;
}

/* http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious */
uint64_t highest_set_bit64(uint64_t val)
{
    uint64_t counter = 0;

    while (val >>= 1)
        counter++;

    return counter;
}

/* http://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend */
int64_t sign_extend64(uint64_t val, uint64_t bits)
{
    int64_t r;
    int64_t const m = 1U << (bits - 1);

    val = val & ((1U << bits) - 1);
    r = (val ^ m) - m;

    return r;
}

/* http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogObvious */
uint32_t highest_set_bit(uint32_t val)
{
    int counter = 0;

    while (val >>= 1)
        counter++;

    return counter;
}

/* http://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend */
int32_t sign_extend(uint32_t val, uint32_t bits)
{
    int32_t r;
    int32_t const m = 1U << (bits - 1);

    val = val & ((1U << bits) - 1);
    r = (val ^ m) - m;

    return r;
}

int ascii_dump(uint8_t* buf, uint64_t count)
{
    if (buf == NULL)
        return EXIT_FAILURE;

    uint64_t i;

    for (i = 0; i < count; i++)
    {
        if (buf[i] <= 31 || buf[i] >= 127)
            fprintf(stdout, ".");
        else
            fprintf(stdout, "%c", (char) buf[i]);
    }

    return EXIT_SUCCESS;
}

int hexdump(uint8_t* buf, uint64_t len)
{
    if (buf == NULL)
        return EXIT_FAILURE;

    uint64_t i, j = 0;

    for (i = 0; i < len; i++)
    {
        if ((j = i % 16) == 0)
        {
            if (i > 0)
            {
                fprintf(stdout, " |");
                ascii_dump(&(buf[i-16]), 16);
                fprintf(stdout, "|\n");
            }
            fprintf(stdout, "%.8"PRIx64, i);
        }

        if (i % 8 == 0)
            fprintf(stdout, " %.2"PRIx8" ", buf[i]);
        else
            fprintf(stdout, "%.2"PRIx8" ", buf[i]);
    }

    /* white space filler */
    j = 15 - j;
    
    if (j >= 8) /* special case, middle has extra space */
        fprintf(stdout, " ");

    while (j > 0)
    {
        fprintf(stdout, "   ");
        j--;
    }        

    if (i > 0)
    {
        fprintf(stdout, " |");
        if (len % 16)
            ascii_dump(&(buf[i-(len % 16)]), len % 16);
        else
            ascii_dump(&(buf[i-16]), 16);
        fprintf(stdout, "|\n");
    }

    return EXIT_SUCCESS;
}

/* buf should be at least 13 bytes long */
int pretty_print_bytes(uint64_t bytes, char* buf, uint64_t bufsize)
{
    if (bytes > TB)
        snprintf(buf, bufsize, "%0.3Lf TiB", ((long double) bytes) / TB);
    else if (bytes > GB)
        snprintf(buf, bufsize, "%0.3Lf GiB", ((long double) bytes) / GB);
    else if (bytes > MB)
        snprintf(buf, bufsize, "%0.3Lf MiB", ((long double) bytes) / MB);
    else if(bytes > KB)
        snprintf(buf, bufsize, "%0.3Lf KiB", ((long double) bytes) / KB);
    else
        snprintf(buf, bufsize, "%"PRIu64" B", bytes);

    return EXIT_SUCCESS;
}

/* buf should be at least 13 bytes long */
int pretty_print_microseconds(uint64_t micros, char* buf, uint64_t bufsize)
{
    if (micros > DAYS)
        snprintf(buf, bufsize, "%0.3Lf days",
                                            ((long double) micros) / DAYS);
    else if (micros > HOURS)
        snprintf(buf, bufsize, "%0.3Lf hours",
                                            ((long double) micros) / HOURS);
    else if (micros > MINUTES)
        snprintf(buf, bufsize, "%0.3Lf minutes",
                                            ((long double) micros ) / MINUTES);
    else if (micros > SECONDS)
        snprintf(buf, bufsize, "%0.3Lf seconds",
                                            ((long double) micros) / SECONDS);
    else if (micros > MILLIS)
        snprintf(buf, bufsize, "%0.3Lf milliseconds",
                                            ((long double) micros) / MILLIS);
    else
        snprintf(buf, bufsize, "%"PRIu64" microseconds", micros);

    return EXIT_SUCCESS;
}

uint64_t diff_time(struct timeval start, struct timeval end)
{
    time_t delta_seconds = end.tv_sec - start.tv_sec;
    suseconds_t delta_micro = end.tv_usec - start.tv_usec;
    uint64_t micros = delta_seconds * 1000000 + delta_micro;
    return micros;
}
