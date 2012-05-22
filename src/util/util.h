#ifndef __UTIL_UTIL_H
#define __UTIL_UTIL_H

#include <inttypes.h>
#include <stdbool.h>

int hexdump(uint8_t* buf, uint64_t len);
bool top_bit_set(uint8_t byte);
uint32_t highest_set_bit(uint32_t val);
int32_t sign_extend(uint32_t val, uint32_t bits);
uint64_t highest_set_bit64(uint64_t val);
int64_t sign_extend64(uint64_t val, uint64_t bits);

#endif
