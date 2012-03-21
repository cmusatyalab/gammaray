#ifndef __STREAM_ANALYZER_DEEP_INSPECT_H
#define __STREAM_ANALYZER_DEEP_INSPECT_H

#include <inttypes.h>
#include "../disk_analyzer/color.h"
#include "../datastructures/bst.h"

#include "qemu_tracer.h"

struct file_sector_map
{
    char* path;
    struct bst_node* tree;
};

int qemu_init_datastructures();
int qemu_deep_inspect(struct qemu_bdrv_write write);
struct bst_node* qemu_get_mapping_bst(char * path);

#endif
