#include "../disk_analyzer/color.h"
#include "bson.h"

#include <assert.h>
#include <stdlib.h>

void test_bson_init(struct bson_info* bson_info)
{
    bson_init(bson_info);
    assert(bson_info->size > 0);
    assert(bson_info->position == 0);
    assert(bson_info->buffer != NULL);
}

void test_bson_cleanup(struct bson_info* bson_info)
{
    bson_cleanup(bson_info);
    assert(bson_info->size == 0);
    assert(bson_info->position == 0);
    assert(bson_info->buffer == NULL);
}

int main(int argc, char* argv[])
{
    struct bson_info bson;

    test_bson_init(&bson);
    test_bson_cleanup(&bson);

    return EXIT_SUCCESS;
}
