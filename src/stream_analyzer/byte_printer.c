#include "byte_printer.h"

int print_bytes(char* bytes, int count)
{
    int i;

    for (i = 0; i < count; i++)
        fputc(bytes[i], stderr);
    return 0;
}
