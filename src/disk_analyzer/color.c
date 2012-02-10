#include "color.h"

const char* CONTROL = "\x1b";
const char* RESET = "[0m";
const char* BOLD = "[1m";
const char* ITALICS = "[3m";
const char* UNDERLINE = "[4m";
const char* INVERSE = "[7m";
const char* STRIKETHROUGH = "[9m";
const char* BOLD_OFF = "[22m";
const char* ITALICS_OFF = "[23m";
const char* UNDERLINE_OFF = "[24m";
const char* INVERSE_OFF = "[25m";
const char* STRIKETHROUGH_OFF = "[29m";
const char* BLACK = "[30m";
const char* RED = "[31m";
const char* GREEN = "[32m";
const char* YELLOW = "[33m";
const char* BLUE = "[34m";
const char* MAGENTA = "[35m";
const char* CYAN = "[36m";
const char* WHITE = "[37m";
const char* DEFAULT = "[39m";
const char* BACKGROUND_BLACK = "[40m";
const char* BACKGROUND_RED = "[41m";
const char* BACKGROUND_GREEN = "[42m";
const char* BACKGROUND_YELLOW = "[43m";
const char* BACKGROUND_BLUE = "[44m";
const char* BACKGROUND_MAGENTA = "[45m";
const char* BACKGROUND_CYAN = "[46m";
const char* BACKGROUND_WHITE = "[47m";
const char* BACKGROUND_DEFAULT = "[49m";

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
    #endif

    return returnv;
}

int fprintf_black(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(BLACK, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_red(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(RED, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_green(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(GREEN, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_yellow(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(YELLOW, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_blue(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(BLUE, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_magenta(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(MAGENTA, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_cyan(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(CYAN, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_white(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(WHITE, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_black(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_mode(BLACK, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_red(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(RED, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_green(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(GREEN, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_yellow(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(YELLOW, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_blue(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(BLUE, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_magenta(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(MAGENTA, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_cyan(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(CYAN, stream, format, args);

    va_end(args);

    return returnv;
}

int fprintf_light_white(FILE * stream, const char * format, ...)
{
    int returnv;
    va_list args;
    va_start(args, format);

    returnv = fprintf_light_mode(WHITE, stream, format, args);

    va_end(args);

    return returnv;
}
