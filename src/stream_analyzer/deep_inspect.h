#ifndef __STREAM_ANALYZER_DEEP_INSPECT_H
#define __STREAM_ANALYZER_DEEP_INSPECT_H

#include <inttypes.h>
#include "../disk_analyzer/color.h"
#include "qemu_tracer.h"

struct file_sector_map
{
    char* path;
    int64_t sectors[];
};

int qemu_deep_inspect(struct qemu_bdrv_write write);

#endif
