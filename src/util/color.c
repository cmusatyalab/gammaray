/*****************************************************************************
 * color.c                                                                   *
 *                                                                           *
 * This file implements colorized versions of fprintf, useful for monitoring *
 * status output on the command line and color-coding log files.             *
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
#include "color.h"

#include <stdarg.h>

#define CONTROL "\x1b"
#define BOLD "[1m"
#define RESET "[0m"
#define BLACK "[30m"
#define RED "[31m"
#define GREEN "[32m"
#define YELLOW "[33m"
#define BLUE "[34m"
#define MAGENTA "[35m"
#define CYAN "[36m"
#define WHITE "[37m"

#define COLOR_FPRINTF(name, color) \
int fprintf_##name(FILE* stream, const char* format, ...) \
{ \
    int returnv;\
    va_list args;\
    va_start(args, format);\
\
    returnv = fprintf_mode(color, stream, format, args);\
\
    va_end(args);\
\
    return returnv;\
}

#define COLOR_LIGHT_FPRINTF(name, color) \
int fprintf_light_##name(FILE* stream, const char* format, ...) \
{ \
    int returnv;\
    va_list args;\
    va_start(args, format);\
\
    returnv = fprintf_light_mode(color, stream, format, args);\
\
    va_end(args);\
\
    return returnv;\
}

int fprintf_light_mode(const char* mode, FILE * stream, const char * format,
                       va_list args)
{
    int returnv;

    #ifndef NOCOLOR
    fprintf(stream, "%s%s", CONTROL, BOLD);
    fprintf(stream, "%s%s", CONTROL, mode);
    #endif
    returnv = vfprintf(stream, format, args);
    #ifndef NOCOLOR
    fprintf(stream, "%s%s", CONTROL, RESET);
    fflush(stream);
    #endif

    return returnv;
}

int fprintf_mode(const char* mode, FILE * stream, const char * format,
                 va_list args)
{
    int returnv;

    #ifndef NOCOLOR
    fprintf(stream, "%s%s", CONTROL, mode);
    #endif
    returnv = vfprintf(stream, format, args);
    #ifndef NOCOLOR
    fprintf(stream, "%s%s", CONTROL, RESET);
    fflush(stream);
    #endif

    return returnv;
}

COLOR_FPRINTF(black, BLACK)
COLOR_FPRINTF(red, RED)
COLOR_FPRINTF(green, GREEN)
COLOR_FPRINTF(yellow, YELLOW)
COLOR_FPRINTF(blue, BLUE)
COLOR_FPRINTF(magenta, MAGENTA)
COLOR_FPRINTF(cyan, CYAN)
COLOR_FPRINTF(white, WHITE)

COLOR_LIGHT_FPRINTF(black, BLACK)
COLOR_LIGHT_FPRINTF(red, RED)
COLOR_LIGHT_FPRINTF(green, GREEN)
COLOR_LIGHT_FPRINTF(yellow, YELLOW)
COLOR_LIGHT_FPRINTF(blue, BLUE)
COLOR_LIGHT_FPRINTF(magenta, MAGENTA)
COLOR_LIGHT_FPRINTF(cyan, CYAN)
COLOR_LIGHT_FPRINTF(white, WHITE)
