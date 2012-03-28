/*
 * This file implements the BSON (v1.0) standard as defined here:
 *  http://bsonspec.org/#/specification
 *
 * */
#include "bson.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Basic Types
 *
 * byte     1 byte  (8-bits)
 * int32    4 bytes (32-bit signed integer)
 * int64    8 bytes (64-bit signed integer)
 * double   8 bytes (64-bit IEEE 754 floating point)
 *
 */

int32_t new_size(int32_t old_size, int32_t needed_size)
{
    while (old_size < needed_size)
    {
        old_size = old_size << 1;
    }
    return old_size;
}

int resize(struct bson_info* bson_info, int32_t needed_size)
{
    uint8_t* old = bson_info->buffer;
    bson_info->size = new_size(bson_info->size, needed_size);
    bson_info->buffer = malloc(bson_info->size);
    
    if (bson_info->buffer == NULL)
        return EXIT_FAILURE;

    if (old)
        free(old);
    
    return EXIT_SUCCESS;
}

int check_size(struct bson_info* bson_info, int32_t added_size)
{
    if (bson_info->position + added_size > bson_info->size)
        return resize(bson_info, bson_info->position + added_size);

    return EXIT_SUCCESS;
}

/* e_name   ::= cstring */
/* cstring  ::= (byte*) "\x00" */
int serialize_cstring(struct bson_info* bson_info, char* str)
{
    int32_t str_size = strlen(str) + 1;

    if (check_size(bson_info, str_size))
        return EXIT_FAILURE;

    memcpy(&(bson_info->buffer[bson_info->position]), str, str_size);
    bson_info->position += str_size;

    return EXIT_SUCCESS;
}

/* string   ::= int32 (byte*) "\x00" */
int serialize_string(struct bson_info* bson_info, char* str)
{
    int32_t str_size = strlen(str) + 1;
    int32_t added_size = str_size + sizeof(int32_t);

    if (check_size(bson_info, added_size))
        return EXIT_FAILURE;
    
    if (added_size > bson_info->size)
    {
        if (resize(bson_info, added_size))
            return EXIT_FAILURE;
    }

    memcpy(&(bson_info->buffer[bson_info->position]), &str_size,  sizeof(str_size));
    bson_info->position += sizeof(str_size);
    memcpy(&(bson_info->buffer[bson_info->position]), str, str_size);
    bson_info->position += str_size;

    return EXIT_SUCCESS;
}

int serialize_double(struct bson_info* bson_info, double* dbl)
{
    int32_t added_size = 8;

    if (check_size(bson_info, added_size))
        return EXIT_FAILURE;

    memcpy(&(bson_info->buffer[bson_info->position]), dbl, added_size);
    bson_info->position += added_size;

    return EXIT_SUCCESS;
}

int serialize_int32(struct bson_info* bson_info, int32_t* int32)
{
    int32_t added_size = 4;

    if (check_size(bson_info, added_size))
        return EXIT_FAILURE;

    memcpy(&(bson_info->buffer[bson_info->position]), int32, added_size);
    bson_info->position += added_size;

    return EXIT_SUCCESS;
}

int serialize_int64(struct bson_info* bson_info, int64_t* int64)
{
    int32_t added_size = 8;

    if (check_size(bson_info, added_size))
        return EXIT_FAILURE;

    memcpy(&(bson_info->buffer[bson_info->position]), int64, added_size);
    bson_info->position += added_size;

    return EXIT_SUCCESS;
}

/*
 * element  ::= "\x01" e_name double
 *         |    "\x02" e_name string            UTF-8 string
 *         |    "\x03" e_name document          Embedded document
 *         |    "\x04" e_name document          Array
 *         |    "\x05" e_name binary
 *         |    "\x06" e_name Undefined         Deprecated
 *         |    "\x07" e_name (byte*12) ObjectId
 *         |    "\x08" e_name "\x00"    Boolean "false"
 *         |    "\x08" e_name "\x01"    Boolean "true"
 *         |    "\x09" e_name int64 UTC datetime
 *         |    "\x0A" e_name Null value
 *         |    "\x0B" e_name cstring cstring   Regular expression
 *         |    "\x0C" e_name string (byte*12)  DBPointer — Deprecated
 *         |    "\x0D" e_name string            JavaScript code
 *         |    "\x0E" e_name string            Symbol
 *         |    "\x0F" e_name code_w_s          JavaScript code w/ scope
 *         |    "\x10" e_name int32             32-bit Integer
 *         |    "\x11" e_name int64             Timestamp
 *         |    "\x12" e_name int64             64-bit integer
 *         |    "\xFF" e_name Min key
 *         |    "\x7F" e_name Max key
 */
int serialize_element(struct bson_info* bson_info, char* key, struct bson_value* value)
{

    check_size(bson_info, 1); /* every element adds 1 byte */

    switch (value->type)
    {
        case BSON_DOUBLE:
            bson_info->buffer[bson_info->position] = BSON_DOUBLE;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_double(bson_info, (double*) value->data);
            break;

        case BSON_STRING:
            bson_info->buffer[bson_info->position] = BSON_STRING;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_string(bson_info, (char*) value->data);
            break;

        case BSON_EMBEDDED_DOCUMENT:
        case BSON_ARRAY:
        case BSON_BINARY: 
        case BSON_UNDEFINED:
        case BSON_OBJECTID:
        case BSON_BOOLEAN:

        case BSON_UTC_DATETIME:
            bson_info->buffer[bson_info->position] = BSON_UTC_DATETIME;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_int64(bson_info, (int64_t*) value->data);
            break;
        
        case BSON_NULL:
        case BSON_REGEX:
        case BSON_DBPOINTER:
        case BSON_JS_CODE:

        case BSON_INT32:
            bson_info->buffer[bson_info->position] = BSON_INT32;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_int32(bson_info, (int32_t*) value->data);
            break;

        case BSON_TIMESTAMP:
            bson_info->buffer[bson_info->position] = BSON_TIMESTAMP;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_int64(bson_info, (int64_t*) value->data);
            break;

        case BSON_INT64:
            bson_info->buffer[bson_info->position] = BSON_INT64;
            bson_info->position++;
            serialize_cstring(bson_info, key);
            serialize_int64(bson_info, (int64_t*) value->data);
            break;

        case BSON_MIN:
        case BSON_MAX:
            break;
    }


    return EXIT_SUCCESS;
}

int bson_finalize(struct bson_info* bson_info)
{
    if (bson_info->buffer)
    {
        if (fwrite(&(bson_info->size), sizeof(bson_info->size), 1,
                   bson_info->file) != sizeof(bson_info->size))
            return EXIT_FAILURE;

        if (fwrite(bson_info->buffer, bson_info->size, 1, bson_info->file) !=
                   bson_info->size)
            return EXIT_FAILURE;
        
        free(bson_info->buffer);
    }
    return EXIT_SUCCESS;
}
