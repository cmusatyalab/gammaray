#ifndef __STREAM_ANALYZER_DEEP_INSPECT_H
#define __STREAM_ANALYZER_DEEP_INSPECT_H

#include <stdbool.h>
#include <inttypes.h>
#include "color.h"
#include "../datastructures/bst.h"

#include "qemu_tracer.h"

struct file_sector_map
{
    char* path;
    struct bst_node* tree;
};

int qemu_init_datastructures();
int qemu_deep_inspect(struct qemu_bdrv_write write);
bool qemu_is_tracked(struct qemu_bdrv_write write);
struct bst_node* qemu_get_mapping_bst(char * path);

#endif
