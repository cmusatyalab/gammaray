#include "__bson.h"
#include "bson.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int bson_print(FILE* stream, struct bson_info* bson)
{
    struct bson_info* embedded;
    struct bson_kv v1;
    struct bson_kv v2;
    time_t utctime;

    fprintf(stream, "{\n");

    while (bson_deserialize(bson, &v1, &v2) == 1) 
    {
        fprintf(stream, "\t'%s' : ", v1.key);
        switch (v1.type)
        {
            case BSON_DOUBLE:
                fprintf(stream, "%f\n", *((double *) v1.data));
                break;
            case BSON_STRING:
                fwrite((uint8_t *) v1.data, v1.size, 1, stream);
                fprintf(stream, "\n");
                break;
            case BSON_EMBEDDED_DOCUMENT:
                fprintf(stream, "BSON_EMBEDDED_DOCUMENT\n");
                break;
            case BSON_ARRAY:
                embedded = bson_init();
                embedded->buffer = malloc(v2.size);
                memcpy(embedded->buffer, v2.data, v2.size);
                bson_make_readable(embedded);
                bson_print(stream, embedded);
                bson_cleanup(embedded);
                break;
            case BSON_BINARY:
                hexdump((uint8_t *) v1.data, v1.size);
                break;
            case BSON_UNDEFINED:
                fprintf(stream, "BSON_UNDEFINED\n");
                break;
            case BSON_OBJECTID:
                fprintf(stream, "BSON_UNDEFINED\n");
                break;
            case BSON_BOOLEAN:
                if (*((uint8_t *) v1.data))
                    fprintf(stream, "true\n");
                else
                    fprintf(stream, "false\n");
                break;
            case BSON_UTC_DATETIME:
                utctime = *((int64_t *) v1.data) / 1000; 
                fprintf(stream, "%s\n", asctime(gmtime(&utctime)));
                break;
            case BSON_NULL:
                fprintf(stream, "NULL\n");
                break;
            case BSON_REGEX:
                fprintf(stream, "BSON_REGEX\n");
                break;
            case BSON_DBPOINTER:
                fprintf(stream, "BSON_DBPOINTER\n");
                break;
            case BSON_JS:
                fprintf(stream, "BSON_JS\n");
                break;
            case BSON_SYMBOL:
                fprintf(stream, "BSON_SYMBOL\n");
                break;
            case BSON_JS_CODE:
                fprintf(stream, "BSON_JS_CODE\n");
                break;
            case BSON_INT32:
                fprintf(stream, "%"PRId32"\n", *((int32_t *) v1.data));
                break;
            case BSON_TIMESTAMP:
                fprintf(stream, "BSON_TIMESTAMP\n");
                break;
            case BSON_INT64:
                fprintf(stream, "%"PRId64"\n", *((int64_t *) v1.data));
                break;
            case BSON_MIN:
                fprintf(stream, "BSON_MIN\n");
                break;
            case BSON_MAX:
                fprintf(stream, "BSON_MAX\n");
                break;
            default:
                fprintf(stream, "\t'%s' : print not implemented\n", v1.key);
                break;
        };
    }

    fprintf (stream, "}\n");

    return EXIT_SUCCESS;
}
