#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bson.h"
#include "__bson.h"
#include "color.h"

int main(int argc, char* argv[])
{
    FILE* f;
    struct bson_info* bson, *bson2;
    struct bson_kv value1, value2;
    int ret;
    uint32_t position;
    int32_t sector;

    fprintf_blue(stderr, "BSON Reverse Index Creator -- By: Wolfgang Richter "
                         "<wolf@cs.cmu.edu>\n");

    if (argc < 2)
    {
        fprintf_light_red(stderr, "Usage: %s <BSON file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    fprintf_cyan(stderr, "Analyzing BSON File: %s\n", argv[1]);

    f = fopen(argv[1], "r");

    if (f == NULL)
    {
        fprintf_light_red(stderr, "Error opening BSON file.\n");
        return EXIT_FAILURE;
    }

    bson = bson_init();
    position = ftell(f);

    /* walk every document */
    while ((ret = bson_readf(bson, f)) == 1)
    {
        /* attempt to read and get document type */
        if (bson_deserialize(bson, &value1, &value2) != 1)
        {
            fprintf_light_red(stderr, "Failed deserializing.\n");
            return EXIT_FAILURE;
        }

        if (strcmp(value1.key, "type") != 0)
        {
            fprintf_light_red(stderr, "Document missing 'type' field.\n");
            return EXIT_FAILURE;
        }
        
        /* if it's a file, find associated sectors and output them */
        if (strcmp(value1.data, "file") == 0)
        {
            while (bson_deserialize(bson, &value1, &value2))
            {
                if ((strcmp(value1.key, "sectors") == 0) ||
                    (strcmp(value1.key, "extents") == 0))
                {
                    
                    bson2 = bson_init();
                    free(bson2->buffer);
                    bson2->buffer = malloc(value2.size);

                    if (bson2->buffer == NULL)
                    {
                        fprintf_light_red(stderr, "malloc() failed\n");
                        return EXIT_FAILURE;
                    }

                    memcpy(bson2->buffer, value2.data, (size_t) value2.size);
                    bson_make_readable(bson2);

                    while (bson_deserialize(bson2, &value1, &value2) == 1)
                    {
                        sector = *((int32_t*) value1.data);
                        sector /= 8;
                        fwrite(&sector, 4, 1, stdout);
                        fwrite(&position, 4, 1, stdout);
                    }
                    bson_cleanup(bson2);
                }
            }
        }

        position = ftell(f);
    }
    
    bson_cleanup(bson);
    fclose(f);

    return EXIT_SUCCESS;
}
