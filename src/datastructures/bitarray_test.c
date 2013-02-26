#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/time.h>

#include "bitarray.h"
#include "color.h"
#include "util.h"

static uint64_t test_nums[] = {
                               0,1,2,3,4,5,6,7,8,9,10,321,478,511,767,
                               777,980,1023,2047,3181,4085,4086,4087,4088,
                               4089,4090,4091,4092,4093,4094,4095
                              };

void test_throughput()
{
    struct bitarray* bits;
    struct timeval start, end;
    char pretty_time[32];
    uint64_t i, time;

    bits = bitarray_init(4294967296);

    for (i = 0; i < 4294967296; i++)
    {
        bitarray_set_bit(bits, i);
    }

    gettimeofday(&start, NULL);
    for (i = 0; i < 4294967296; i++)
    {
        assert(bitarray_get_bit(bits, i) == true);
    }
    gettimeofday(&end, NULL);

    time = diff_time(start, end);
    pretty_print_microseconds(time, pretty_time, 32);
    fprintf_cyan(stdout, "time to get 4294967296 items and check set: %s\n",
                         pretty_time);
    bitarray_destroy(bits);
}

int main(int argc, char* argv[])
{
    uint64_t i;
    struct bitarray* bits;

    fprintf_blue(stdout, "-- Bitarray Test Suite --\n");

    fprintf_light_blue(stdout, "* test bitarray_init()\n");
    bits = bitarray_init(8*512);
    bitarray_print(bits);
    fprintf_light_blue(stdout, "* test bitarray_set_all()\n");
    bitarray_set_all(bits);
    bitarray_print(bits);
    fprintf_light_blue(stdout, "* test bitarray_clear()\n");
    bitarray_unset_all(bits);
    bitarray_print(bits);

    fprintf_light_blue(stdout, "* test bitarray_set_bit()\n");
    for (i = 0; i < 31; i++)
    {
        bitarray_set_bit(bits, test_nums[i]);
    }

    fprintf_light_blue(stdout, "* test bitarray_get_bit()\n");
    for (i = 0; i < 31; i++)
    {
        assert(bitarray_get_bit(bits, test_nums[i]) == true);
    }


    fprintf_light_blue(stdout, "* test bitarray_unset_bit()\n");
    bitarray_unset_bit(bits, test_nums[4]);
    bitarray_unset_bit(bits, test_nums[9]);
    for (i = 0; i < 31; i++)
    {
        if (i == 4 || i == 9) continue;
        assert(bitarray_get_bit(bits, test_nums[i]) == true);
    }

    for (i = 0; i < 31; i++)
    {
        bitarray_unset_bit(bits, test_nums[i]);
    }

    for (i = 0; i < 31; i++)
    {
        assert(bitarray_get_bit(bits, test_nums[i]) == false);
    }

    bitarray_print(bits);

    bitarray_destroy(bits);

    test_throughput();

    return EXIT_SUCCESS;
}
