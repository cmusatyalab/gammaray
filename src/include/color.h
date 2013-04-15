/*****************************************************************************
 * color.h                                                                   *
 *                                                                           *
 * This file contains prototypes for colorized versions of fprintf, suitable *
 * for including in other C files within a project.                          *
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
#ifndef __GAMMARAY_UTIL_COLOR_H
#define __GAMMARAY_UTIL_COLOR_H

#include <stdio.h>

int fprintf_black(FILE * stream, const char * format, ...);
int fprintf_red(FILE * stream, const char * format, ...);
int fprintf_blue(FILE * stream, const char * format, ...);
int fprintf_green(FILE * stream, const char * format, ...);
int fprintf_yellow(FILE * stream, const char * format, ...);
int fprintf_magenta(FILE * stream, const char * format, ...);
int fprintf_cyan(FILE * stream, const char * format, ...);
int fprintf_white(FILE * stream, const char * format, ...);
int fprintf_light_black(FILE * stream, const char * format, ...);
int fprintf_light_red(FILE * stream, const char * format, ...);
int fprintf_light_blue(FILE * stream, const char * format, ...);
int fprintf_light_green(FILE * stream, const char * format, ...);
int fprintf_light_yellow(FILE * stream, const char * format, ...);
int fprintf_light_magenta(FILE * stream, const char * format, ...);
int fprintf_light_cyan(FILE * stream, const char * format, ...);
int fprintf_light_white(FILE * stream, const char * format, ...);

#endif
