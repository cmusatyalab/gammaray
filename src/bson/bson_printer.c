#include <stdio.h>
#include <stdlib.h>

#include "bson.h"
#include "color.h"

int main(int argc, char* argv[])
{
    struct bson_info* bson;

    fprintf_blue(stdout, "BSON Printer -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: %s <BSON file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stdout, "Analyzing BSON File: %s\n", argv[1]);

    bson = bson_init();
    bson_read(bson, argv[1]);
    bson_print(stdout, bson);
    bson_cleanup(bson);

    return EXIT_SUCCESS;
}
