#ifndef __XRAY_UTIL_BSON_H
#define __XRAY_UTIL_BSON_H

#include <stdio.h>
#include <inttypes.h>

enum BSON_TYPE
{
    BSON_DOUBLE = 0x01,
    BSON_STRING = 0x02,
    BSON_EMBEDDED_DOCUMENT = 0x03,
    BSON_ARRAY = 0x04,
    BSON_BINARY = 0x05,
    BSON_UNDEFINED = 0x06,          /* DEPRECATED */
    BSON_OBJECTID = 0x07,           /* 12 bytes */
    BSON_BOOLEAN = 0x08,
    BSON_UTC_DATETIME = 0x09,
    BSON_NULL = 0x0a,
    BSON_REGEX = 0x0b,
    BSON_DBPOINTER = 0x0c,
    BSON_JS = 0x0d,                 /* JS code */
    BSON_SYMBOL = 0x0e,             /* symbol */
    BSON_JS_CODE = 0x0f,            /* includes scope */
    BSON_INT32 = 0x10,              /* 32 bit signed */
    BSON_TIMESTAMP = 0x11,          /* MongoDB-specific timestamp */
    BSON_INT64 = 0x12,              /* 64 bit signed */
    BSON_MIN = 0xff,                /* minimum key by comparison */
    BSON_MAX = 0x7f                 /* maximum key by comparison */
};

enum BSON_SUBTYPE
{
    BSON_BINARY_GENERIC = 0x00,
    BSON_FUNCTION = 0x01,
    BSON_BINARY_OLD = 0x02,
    BSON_UUID = 0x03,
    BSON_MD5 = 0x05,
    BSON_USER = 0x80
};

struct bson_info
{
    int32_t size;
    int32_t position;
    uint8_t* buffer;
};

struct bson_value
{
    enum BSON_TYPE type;
    enum BSON_SUBTYPE subtype;
    void* data;
};

int bson_init(struct bson_info* bson_info);
int bson_serialize(struct bson_info* bson_info, char* key,
                   struct bson_value value);
int bson_finalize(struct bson_info* bson_info);
int bson_write(struct bson_info* bson_info, FILE* file);
void bson_cleanup(struct bson_info* bson_info);

#endif
