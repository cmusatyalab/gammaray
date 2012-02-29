/*****************************************************************************
 * Author: Wolfgang Richter <wolf@cs.cmu.edu>                                *
 * Purpose: Analyze a stream of disk block writes and infere file-level      *
 *          mutations given context from a pre-indexed raw disk image.       *
 *                                                                           *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "../disk_analyzer/color.h"

/* main thread of execution */
int main(int argc, char* args[])
{
    FILE* index;
    fprintf_blue(stdout, "Virtual Block Write Stream Analyzer -- "
                         "By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: ./%s <disk index file>\n", args[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Loading index: %s\n\n", args[1]);

    index = fopen(args[1], "r");
    
    if (index == NULL)
    {
        fprintf_light_red(stderr, "Error opening index file. "
                                  "Does it exist?\n");
        return EXIT_FAILURE;
    }

    fclose(index);

    return EXIT_SUCCESS;
}
