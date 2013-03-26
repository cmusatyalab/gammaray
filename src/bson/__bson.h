#ifndef __BSON___BSON_H
#define __BSON___BSON_H

#include <inttypes.h>

struct bson_info
{
    uint64_t size;
    uint64_t f_offset;
    uint64_t position;
    uint8_t* buffer;
};

#endif
