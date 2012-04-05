#include "../disk_analyzer/color.h"
#include "bson.h"
#include "util.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

void test_bson_init(struct bson_info* bson_info)
{
    assert(bson_info);
    
    bson_init(bson_info);
    
    assert(bson_info->size > 0);
    assert(bson_info->position == 0);
    assert(bson_info->buffer != NULL);
}

void test_bson_cleanup(struct bson_info* bson_info)
{
    assert(bson_info);
    
    bson_cleanup(bson_info);
    
    assert(bson_info->size == 0);
    assert(bson_info->position == 0);
    assert(bson_info->buffer == NULL);
}

void test_bson_serialize(struct bson_info* bson_info, char* key,
                         struct bson_value* value)
{
    assert(bson_info);
    assert(bson_info->buffer);
    assert(key);
    assert(value);
    assert(value->data);
    int32_t old_position = bson_info->position;
    int32_t old_size = bson_info->size;
    
    bson_serialize(bson_info, key, value);
    
    assert(bson_info->size >= old_size);
    assert(bson_info->position > old_position);
    assert(bson_info->buffer);
}

void test_bson_finalize(struct bson_info* bson_info)
{
    assert(bson_info);
    assert(bson_info->buffer);
    assert(bson_info->buffer);
    int32_t old_position = bson_info->position;
    int32_t old_size = bson_info->size;

    bson_finalize(bson_info);
    
    assert(bson_info->size >= old_size);
    assert(bson_info->position > old_position);
    assert(bson_info->buffer);
    assert(((uint8_t*)bson_info->buffer)[bson_info->position-1] == 0x00);
    assert(*((int32_t*)bson_info->buffer) >= 0);
}

int main(int argc, char* argv[])
{
    struct bson_info bson;


    test_bson_init(&bson);
    fprintf_light_green(stderr, "Passed test_bson_init.\n");


    double val1d = 3.1415926;
    struct bson_value val1 = {
                                .type = BSON_DOUBLE,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &val1d
                             };

    test_bson_serialize(&bson, "test1d", &val1);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize1.\n");
    
    
    int32_t val2i32 = 37684;
    struct bson_value val2 = {
                                .type = BSON_INT32,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &val2i32
                             };

    test_bson_serialize(&bson, "test2i32", &val2);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize2.\n");
    
    
    int64_t val3i64 = 3768400;
    struct bson_value val3 = {
                                .type = BSON_INT64,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &val3i64
                             };

    test_bson_serialize(&bson, "test3i64", &val3);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize3.\n");
    

    char* val4str = "testerrrrrstring";
    int32_t len4 = strlen(val4str);
    uint8_t buf4[strlen(val4str)+4];
    memmove(&buf4[4], val4str, strlen(val4str));
    memcpy(&buf4, &len4, 4);
    struct bson_value val4 = {
                                .type = BSON_STRING,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &buf4
                             };

    test_bson_serialize(&bson, "test4str", &val4);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize4.\n");
    

    int32_t len5 = 6;
    char val5bin[6] = {0xff,0xde,0xad,0xbe,0xef,0xff};
    uint8_t buf5[10];
    memcpy(&buf5[4], val5bin, len5);
    memcpy(&buf5, &len5, 4);
    struct bson_value val5 = {
                                .type = BSON_BINARY,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &buf5
                              };

    test_bson_serialize(&bson, "test5bin", &val5);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize5.\n");

    bool true6 = true;
    struct bson_value val6 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &true6
                              };

    test_bson_serialize(&bson, "test6true", &val6);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize6.\n");

    bool true7 = false;
    struct bson_value val7 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &true7
                              };

    test_bson_serialize(&bson, "test7false", &val7);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize7.\n");

    struct bson_value val8 = {
                                .type = BSON_NULL,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = (void*) 0xffff /* shouldn't be used */ 
                              };

    test_bson_serialize(&bson, "test8NULL", &val8);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize8.\n");

    struct bson_value val9 = {
                                .type = BSON_ARRAY,
                                .subtype = BSON_BINARY_GENERIC,
                                .data = &bson 
                              };

    test_bson_serialize(&bson, "test9arrayself", &val9);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_serialize9.\n");

    test_bson_finalize(&bson);
    hexdump(bson.buffer, bson.position);
    fprintf_light_green(stderr, "Passed test_bson_finalize.\n");

    test_bson_cleanup(&bson);
    fprintf_light_green(stderr, "Passed test_bson_cleanup.\n");

    return EXIT_SUCCESS;
}
