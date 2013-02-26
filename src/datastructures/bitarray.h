#ifndef __BITARRAY_H
#define __BITARRAY_H

#include <stdint.h>
#include <stdbool.h>

struct bitarray;

bool bitarray_get_bit(struct bitarray* bits, uint64_t bit);
void bitarray_set_bit(struct bitarray* bits, uint64_t bit);
void bitarray_unset_bit(struct bitarray* bits, uint64_t bit);
void bitarray_set_all(struct bitarray* bits);
void bitarray_unset_all(struct bitarray* bits);
void bitarray_print(struct bitarray* bits);
struct bitarray* bitarray_init(uint64_t len);
void bitarray_destroy(struct bitarray* bits);
uint64_t bitarray_get_array(struct bitarray* bits, uint8_t** array);

#endif
