#include "__bson.h" /* internal lib header */
#include "bson.h"
#include "color.h"
#include "util.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

void test_bson_init(struct bson_info** bson_info)
{
    assert(bson_info);
    
    *bson_info = bson_init();
    
    assert((*bson_info)->size > 0);
    assert((*bson_info)->position == 0);
    assert((*bson_info)->buffer != NULL);
}

void test_bson_cleanup(struct bson_info* bson_info)
{
    assert(bson_info);
    
    bson_cleanup(bson_info); /* bson_info unusable after this call */
}

void test_bson_serialize(struct bson_info* bson_info, struct bson_kv* value)
{
    assert(bson_info);
    assert(bson_info->buffer);
    assert(value->key);
    assert(value);
    assert(value->data);
    int32_t old_position = bson_info->position;
    int32_t old_size = bson_info->size;
    
    bson_serialize(bson_info, value);
    
    assert(bson_info->size >= old_size);
    assert(bson_info->position > old_position);
    assert(bson_info->buffer);
}

void test_bson_finalize(struct bson_info* bson_info)
{
    assert(bson_info);
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

void test_bson_make_readable(struct bson_info* bson_info)
{
    assert(bson_info);
    assert(bson_info->buffer);
    int32_t old_position = bson_info->position;

    bson_make_readable(bson_info);

    assert(bson_info->position == 4);
    assert(bson_info->size == old_position - 4);
}

void test_bson_deserialize(struct bson_info* bson_info,
                           struct bson_kv* val_d_1,
                           struct bson_kv* val_d_2)
{
    assert(bson_info);
    assert(bson_info->buffer);
    int32_t old_position = bson_info->position;
    int32_t old_size = bson_info->size;

    assert(bson_deserialize(bson_info, val_d_1, val_d_2) == 1);
    
    assert(bson_info->position > old_position);
    assert(bson_info->size < old_size);
}

void test_encoding()
{
    struct bson_info* bson;


    test_bson_init(&bson);
    fprintf_light_green(stderr, "Passed test_bson_init.\n");


    double val1d = 3.1415926;
    struct bson_kv val1 = {
                                .type = BSON_DOUBLE,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test1d",
                                .data = &val1d
                             };

    test_bson_serialize(bson, &val1);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize1.\n");
    
    
    int32_t val2i32 = 37684;
    struct bson_kv val2 = {
                                .type = BSON_INT32,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test2i32",
                                .data = &val2i32
                             };

    test_bson_serialize(bson, &val2);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize2.\n");
    
    
    int64_t val3i64 = 3768400;
    struct bson_kv val3 = {
                                .type = BSON_INT64,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test3i64",
                                .data = &val3i64
                             };

    test_bson_serialize(bson, &val3);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize3.\n");
    

    char* val4str = "testerrrrrstring";
    int32_t len4 = strlen(val4str);
    uint8_t buf4[strlen(val4str)];
    memmove(buf4, val4str, strlen(val4str));
    struct bson_kv val4 = {
                                .type = BSON_STRING,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test4str",
                                .data = buf4,
                                .size = len4
                             };

    test_bson_serialize(bson, &val4);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize4.\n");
    

    int32_t len5 = 6;
    char val5bin[6] = {0xff,0xde,0xad,0xbe,0xef,0xff};
    uint8_t buf5[6];
    memcpy(&buf5[4], val5bin, len5);
    struct bson_kv val5 = {
                                .type = BSON_BINARY,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test5bin",
                                .data = buf5,
                                .size = len5
                              };
    test_bson_serialize(bson, &val5);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize5.\n");

    bool true6 = true;
    struct bson_kv val6 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test6true",
                                .data = &true6
                              };

    test_bson_serialize(bson, &val6);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize6.\n");

    bool true7 = false;
    struct bson_kv val7 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test7false",
                                .data = &true7
                              };

    test_bson_serialize(bson, &val7);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize7.\n");

    struct bson_kv val8 = {
                                .type = BSON_NULL,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test8NULL",
                                .data = (void*) 0xffff /* shouldn't be used */ 
                              };

    test_bson_serialize(bson, &val8);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize8.\n");

    struct bson_kv val9 = {
                                .type = BSON_ARRAY,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test9arrayself",
                                .data = bson 
                              };

    test_bson_serialize(bson, &val9);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize9.\n");

    test_bson_finalize(bson);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_finalize.\n");

    test_bson_cleanup(bson);
    fprintf_light_green(stderr, "Passed test_bson_cleanup.\n");
}

void test_decoding()
{
    struct bson_info* bson;


    test_bson_init(&bson);
    fprintf_light_green(stderr, "Passed test_bson_init.\n");


    double val1d = 3.1415926;
    struct bson_kv val1 = {
                                .type = BSON_DOUBLE,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test1d",
                                .data = &val1d
                             };

    test_bson_serialize(bson, &val1);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize1.\n");
    
    
    int32_t val2i32 = 37684;
    struct bson_kv val2 = {
                                .type = BSON_INT32,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test2i32",
                                .data = &val2i32
                             };

    test_bson_serialize(bson, &val2);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize2.\n");
    
    
    int64_t val3i64 = 3768400;
    struct bson_kv val3 = {
                                .type = BSON_INT64,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test3i64",
                                .data = &val3i64
                             };

    test_bson_serialize(bson, &val3);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize3.\n");
    

    char* val4str = "testerrrrrstring";
    int32_t len4 = strlen(val4str);
    uint8_t buf4[strlen(val4str)];
    memmove(buf4, val4str, strlen(val4str));
    struct bson_kv val4 = {
                                .type = BSON_STRING,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test4str",
                                .data = buf4,
                                .size = len4
                             };

    test_bson_serialize(bson, &val4);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize4.\n");
    

    int32_t len5 = 6;
    char val5bin[6] = {0xff,0xde,0xad,0xbe,0xef,0xff};
    uint8_t buf5[6];
    memcpy(buf5, val5bin, len5);
    struct bson_kv val5 = {
                                .type = BSON_BINARY,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test5bin",
                                .data = &buf5,
                                .size = len5
                              };
    test_bson_serialize(bson, &val5);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize5.\n");

    bool true6 = true;
    struct bson_kv val6 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test6true",
                                .data = &true6
                              };

    test_bson_serialize(bson, &val6);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize6.\n");

    bool true7 = false;
    struct bson_kv val7 = {
                                .type = BSON_BOOLEAN,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test7false",
                                .data = &true7
                              };

    test_bson_serialize(bson, &val7);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize7.\n");

    struct bson_kv val8 = {
                                .type = BSON_NULL,
                                .subtype = BSON_BINARY_GENERIC,
                                .key = "test8NULL",
                                .data = (void*) 0xffff /* shouldn't be used */ 
                              };

    test_bson_serialize(bson, &val8);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_serialize8.\n");

    test_bson_finalize(bson);
    hexdump(bson->buffer, bson->position);
    fprintf_light_green(stderr, "Passed test_bson_finalize.\n");
    
    test_bson_make_readable(bson);

    struct bson_kv val_d_1;
    struct bson_kv val_d_2;
    uint64_t old_position = 0;
    uint64_t old_size = 0;
    uint64_t parsed = 0;

    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test1d") + 1 + 8;
    
    assert(val_d_1.type == BSON_DOUBLE);
    assert(strcmp(val_d_1.key, "test1d") == 0);
    assert(*((double *) val_d_1.data) == val1d);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

    
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test2i32") + 1 + 4;

    assert(val_d_1.type == BSON_INT32);
    assert(strcmp(val_d_1.key, "test2i32") == 0);
    assert(*((int32_t *) val_d_1.data) == val2i32);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);
    
    
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test3i64") + 1 + 8;

    assert(val_d_1.type == BSON_INT64);
    assert(strcmp(val_d_1.key, "test3i64") == 0);
    assert(*((int64_t *) val_d_1.data) == val3i64);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

    
    old_position = bson->position;
    old_size = bson->size;


    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test4str") + 1 + strlen(val4str) + 1 + 4; 

    assert(val_d_1.type == BSON_STRING);
    assert(val_d_1.size == strlen(val4str));
    assert(strcmp(val_d_1.key, "test4str") == 0);
    assert(strncmp(((char *) val_d_1.data), val4str, strlen(val4str)) == 0);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);


    
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test5bin") + 1 + 1 + 6 + 4; 

    assert(val_d_1.type == BSON_BINARY);
    assert(val_d_1.subtype == BSON_BINARY_GENERIC);
    assert(val_d_1.size == 6);
    assert(strcmp(val_d_1.key, "test5bin") == 0);
    assert(strncmp(((char *) val_d_1.data), val5bin, 6) == 0);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

    
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test6true") + 1 + 1; 

    assert(val_d_1.type == BSON_BOOLEAN);
    assert(val_d_1.size == 1);
    assert(strcmp(val_d_1.key, "test6true") == 0);
    assert(*((uint8_t *)val_d_1.data) == 1);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

    
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test7false") + 1 + 1; 

    assert(val_d_1.type == BSON_BOOLEAN);
    assert(val_d_1.size == 1);
    assert(strcmp(val_d_1.key, "test7false") == 0);
    assert(*((uint8_t *)val_d_1.data) == 0);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

   
    old_position = bson->position;
    old_size = bson->size;

    test_bson_deserialize(bson, &val_d_1, &val_d_2);
    parsed = 1 + strlen("test8NULL") + 1; 

    assert(val_d_1.type == BSON_NULL);
    assert(val_d_1.size == 0);
    assert(strcmp(val_d_1.key, "test8NULL") == 0);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);
   

    old_position = bson->position;
    old_size = bson->size;

    parsed = 1; /* final 0x00 */

    assert(bson_deserialize(bson, &val_d_1, &val_d_2) == 0);
    assert(bson->position == old_position + parsed);
    assert(bson->size == old_size - parsed);

    fprintf_light_green(stderr, "Passed all deserialization tests\n");

    test_bson_cleanup(bson);
    fprintf_light_green(stderr, "Passed test_bson_cleanup.\n");
}

int main(int argc, char* argv[])
{
    test_encoding();
    test_decoding();
    return EXIT_SUCCESS;
}
