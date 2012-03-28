#include "util.h"
#include "../disk_analyzer/color.h"

#include <stdio.h>
#include <stdlib.h>

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
