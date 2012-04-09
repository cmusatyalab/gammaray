#include "color.h"

#define CONTROL "\x1b"
#define RESET "[0m"
#define BOLD "[1m"
#define ITALICS "[3m"
#define UNDERLINE "[4m"
#define INVERSE "[7m"
#define STRIKETHROUGH "[9m"
#define BOLD_OFF "[22m"
#define ITALICS_OFF "[23m"
#define UNDERLINE_OFF "[24m"
#define INVERSE_OFF "[25m"
#define STRIKETHROUGH_OFF "[29m"
#define BLACK "[30m"
#define RED "[31m"
#define GREEN "[32m"
#define YELLOW "[33m"
#define BLUE "[34m"
#define MAGENTA "[35m"
#define CYAN "[36m"
#define WHITE "[37m"
#define DEFAULT "[39m"
#define BACKGROUND_BLACK "[40m"
#define BACKGROUND_RED "[41m"
#define BACKGROUND_GREEN "[42m"
#define BACKGROUND_YELLOW "[43m"
#define BACKGROUND_BLUE "[44m"
#define BACKGROUND_MAGENTA "[45m"
#define BACKGROUND_CYAN "[46m"
#define BACKGROUND_WHITE "[47m"
#define BACKGROUND_DEFAULT "[49m"

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
