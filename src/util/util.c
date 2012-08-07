#include "util.h"
#include "color.h"

#include <stdio.h>
#include <stdlib.h>

bool top_bit_set(uint8_t byte)
{
    return (0x80 & byte) == 0x80;
}

/* http://stackoverflow.com/posts/4970859/revisions */
uint64_t highest_set_bit64(uint64_t val)
{
    int counter = 0;

    while (val >>= 1)
    {
        counter++;
    }

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

/* http://stackoverflow.com/posts/4970859/revisions */
uint32_t highest_set_bit(uint32_t val)
{
    int counter = 0;

    while (val >>= 1)
    {
        counter++;
    }

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

    uint64_t i, j;

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
    uint64_t kb = 1024;
    uint64_t mb = kb*kb;
    uint64_t gb = kb*mb;
    uint64_t tb = kb*gb;

    if (bytes > tb)
    {
        snprintf(buf, bufsize, "%0.3f TiB", ((double) bytes) / tb);
    }
    else if (bytes > gb)
    {
        snprintf(buf, bufsize, "%0.3f GiB", ((double) bytes) / gb);
    }
    else if (bytes > mb)
    {
        snprintf(buf, bufsize, "%0.3f MiB", ((double) bytes) / mb);
    }
    else if(bytes > kb)
    {
        snprintf(buf, bufsize, "%0.3f KiB", ((double) bytes) / kb);
    }
    else
    {
        snprintf(buf, bufsize, "%"PRIu64" B", bytes);
    }

    return EXIT_SUCCESS;
}
