#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "color.h"
#include "bitarray.h"
#include "util.h"

struct bitarray
{
    uint8_t* array;
    uint64_t len;
};

bool bitarray_get_bit(struct bitarray* bits, uint64_t bit)
{
    if (bit < bits->len)
        return bits->array[bit/8] & (1 << (bit & 0x07));
    else
        return false;
}

void bitarray_set_bit(struct bitarray* bits, uint64_t bit)
{
    if (bit < bits->len)
        bits->array[bit/8] |= 1 << (bit & 0x07);
}

void bitarray_unset_bit(struct bitarray* bits, uint64_t bit)
{
    if (bit < bits->len)
        bits->array[bit/8] &= (0xff ^ (1 << (bit & 0x07)));
}

void bitarray_set_all(struct bitarray* bits)
{
    memset(bits->array, 0xff, bits->len / 8);
}

void bitarray_unset_all(struct bitarray* bits)
{
    memset(bits->array, 0x00, bits->len / 8);
}

void bitarray_print(struct bitarray* bits)
{
    fprintf_yellow(stdout, "bits->array [pointer]: %p\n", bits->array);
    fprintf_yellow(stdout, "bits->len [bits]: %"PRIu64"\n", bits->len);
    fprintf_light_yellow(stdout, " -- hexdump(bits->array) -- \n");
    hexdump(bits->array, bits->len / 8);
    fprintf_light_yellow(stdout, " -- end hexdump(bits->array) -- \n");
}

struct bitarray* bitarray_init(uint64_t len)
{
    struct bitarray* bits = (struct bitarray*) malloc(sizeof(struct bitarray));

    if (bits)
    {
        bits->len = ((uint64_t) 1) << (uint64_t) ((log((double) len) / log(2)) + 0.5);
        bits->array = (uint8_t*) malloc((bits->len + 7) / 8);
        bitarray_unset_all(bits);
    }

    return bits;
}

struct bitarray* bitarray_init_data(uint8_t* data, uint64_t len)
{
    struct bitarray* bits = (struct bitarray*) malloc(sizeof(struct bitarray));

    if (bits)
    {
        bits->len = ((uint64_t) 1) << (uint64_t) ((log((double) len) / log(2)) + 0.5);
        bits->array = (uint8_t*) malloc((bits->len + 7) / 8);
        memcpy(bits->array, data, len / 8);
    }

    return bits;
}

void bitarray_destroy(struct bitarray* bits)
{
    if (bits)
    {
        if (bits->array)
            free(bits->array);
        bits->array = NULL;
        free(bits);
    }
}

uint64_t bitarray_get_array(struct bitarray* bits, uint8_t** array)
{
    *array = bits->array;
    return bits->len / 8;
}
