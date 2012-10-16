#include "bson.h"
#include "__bson.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

off_t fsize(const char* path)
{
    struct stat st;

    if (stat(path, &st))
        return -1;

    return st.st_size;
}

int bson_make_readable(struct bson_info* bson_info)
{
    if (bson_info == NULL || bson_info->buffer == NULL || bson_info->size < 5)
        return EXIT_FAILURE;
    bson_info->size = *((int32_t*) bson_info->buffer) - 4;
    bson_info->position = 4;
    return EXIT_SUCCESS;
}

int bson_readf(struct bson_info* bson_info, FILE* file)
{
    int32_t size;
    if (bson_info == NULL)
        return 0;

    if (file == NULL)
        return 0;

    if (fread(&(size), 4, 1, file) != 1)
    {
        return 0;
    }

    size -= 4;

    if (bson_info->size < size && bson_info->buffer != NULL)
    {
        free(bson_info->buffer);
        bson_info->buffer = NULL;
        bson_info->buffer = malloc(size);
    }
    else if (bson_info->buffer == NULL)
    {
        bson_info->buffer = malloc(size);
    }

    if (bson_info->buffer)
    {
        if(fread(bson_info->buffer, 1, size, file) != size)
        {
            return -1;
        }
        bson_info->size = size;
        bson_info->position = 0;
        return 1;
    }

    return -1;
}

int bson_read(struct bson_info* bson_info, const char* fname)
{
    if (bson_info == NULL)
        return EXIT_FAILURE;

    off_t size = fsize(fname);
    FILE* file = fopen(fname, "r");

    if (file == NULL)
        return EXIT_FAILURE;

    if (bson_info->buffer != NULL)
        free(bson_info->buffer);

    bson_info->buffer = malloc(size);
    if (bson_info->buffer)
    {
        if(fread(bson_info->buffer, 1, size, file) != size)
        {
            fclose(file);
            return EXIT_FAILURE;
        }
        bson_make_readable(bson_info);
        fclose(file);
        return EXIT_SUCCESS;
    }

    fclose(file);

    return EXIT_FAILURE;
}

int deserialize_cstring(struct bson_info* bson_info, struct bson_kv* kv)
{
    if (bson_info == NULL || bson_info->buffer == NULL || kv == NULL)
        return EXIT_FAILURE;

    kv->data = &(bson_info->buffer[bson_info->position]);

    bson_info->position += strlen(kv->data) + 1;
    bson_info->size -= strlen(kv->data) + 1;

    if (bson_info->position > bson_info->size)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int deserialize_string(struct bson_info* bson_info, struct bson_kv* kv)
{
    if (bson_info == NULL || bson_info->buffer == NULL || kv == NULL)
        return EXIT_FAILURE;

    kv->size = *((int32_t*) &(bson_info->buffer[bson_info->position])) - 1;
    bson_info->position += 4;
    bson_info->size -= 4;
    kv->data = &(bson_info->buffer[bson_info->position]);

    bson_info->position += kv->size + 1;
    bson_info->size -= kv->size + 1;

    if (bson_info->position > bson_info->size)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int deserialize_document(struct bson_info* bson_info, struct bson_kv* kv)
{
    if (bson_info == NULL || bson_info->buffer == NULL || kv == NULL)
        return EXIT_FAILURE;

    kv->size = *((int32_t*) &(bson_info->buffer[bson_info->position]));
    kv->data = &(bson_info->buffer[bson_info->position]);

    bson_info->position += kv->size;
    bson_info->size -= kv->size;

    return EXIT_SUCCESS;
}

/**
 *
 * @return 0 - end of document, 1 - object deserialized, -1 error encountered
 *
 */
int bson_deserialize(struct bson_info* bson_info, struct bson_kv* value,
                     struct bson_kv* value2)
{
    if (bson_info->size < 1)
        return 0;

    if (bson_info->size == 1)
    {
        assert(bson_info->buffer[bson_info->position] == 0);
        bson_info->position++;
        bson_info->size--;
        return 0;
    }

    value->type = bson_info->buffer[bson_info->position];
    bson_info->position++;
    bson_info->size--;

    deserialize_cstring(bson_info, value);
    value->key = value->data;
    value->size = 0;

    switch(value->type)
    {
        case BSON_DOUBLE:
            value->data = &(bson_info->buffer[bson_info->position]);
            value->size = 8;
            bson_info->position += 8;
            bson_info->size -= 8;
            break;
        case BSON_STRING:
            deserialize_string(bson_info, value);
            break;
        case BSON_EMBEDDED_DOCUMENT:
            deserialize_document(bson_info, value2);
            break;
        case BSON_ARRAY:
            deserialize_document(bson_info, value2);
            break;
        case BSON_BINARY:
            value->size = *((int32_t *)
                            (&bson_info->buffer[bson_info->position]));
            bson_info->position += 4;
            bson_info->size -= 4;
            value->subtype = *((uint8_t *)
                               (&bson_info->buffer[bson_info->position]));
            bson_info->position += 1;
            bson_info->size -= 1;
            value->data = &(bson_info->buffer[bson_info->position]);
            bson_info->position += value->size;
            bson_info->size -= value->size;
            break;
        case BSON_UNDEFINED:
            /* finished */
            break;
        case BSON_OBJECTID:
            value->data = &(bson_info->buffer[bson_info->position]);
            bson_info->position += 12;
            bson_info->size -= 12;
            break;
        case BSON_BOOLEAN:
            value->data = &(bson_info->buffer[bson_info->position]);
            value->size = 1;
            bson_info->position += 1;
            bson_info->size -= 1;
            break;
        case BSON_UTC_DATETIME:
            value->data = &(bson_info->buffer[bson_info->position]);
            bson_info->position += 8;
            bson_info->size -= 8;
            break;
        case BSON_NULL:
            /* finished */
            break;
        case BSON_REGEX:
            value2->key = value->key;
            deserialize_cstring(bson_info, value);
            deserialize_cstring(bson_info, value2);
            break;
        case BSON_DBPOINTER:
            value2->key = value->key;
            deserialize_string(bson_info, value);
            value2->data = &(bson_info->buffer[bson_info->position]);
            bson_info->position += 12;
            bson_info->size -= 12;
            break;
        case BSON_JS:
            deserialize_string(bson_info, value);
            break;
        case BSON_SYMBOL:
            deserialize_string(bson_info, value);
            break;
        case BSON_JS_CODE:
            bson_info->position += 4; /* skip int32_t size */
            bson_info->size -= 4; /* skip int32_t size */
            deserialize_string(bson_info, value);
            value2->key = value->key;
            deserialize_document(bson_info, value2);
            break;
        case BSON_INT32:
            value->data = &(bson_info->buffer[bson_info->position]);
            value->size = 4;
            bson_info->position += 4;
            bson_info->size -= 4;
            break;
        case BSON_TIMESTAMP:
            value->data = &(bson_info->buffer[bson_info->position]);
            bson_info->position += 8;
            bson_info->size -= 8;
            break;
        case BSON_INT64:
            value->data = &(bson_info->buffer[bson_info->position]);
            value->size = 8;
            bson_info->position += 8;
            bson_info->size -= 8;
            break;
        case BSON_MIN:
            /* finished */
            break;
        case BSON_MAX:
            /* finished */
            break;
        default:
            return -1;
    };

    return 1;
}
