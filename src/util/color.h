/* This file defines ANSI color codes and function definitions for printing in
 * color. */

#ifndef XRAY_DISK_ANALYZER_COLOR_H
#define XRAY_DISK_ANALYZER_COLOR_H

#include <stdarg.h>
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
