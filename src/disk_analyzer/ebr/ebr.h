#ifndef __XRAY_DISK_ANALYZER_EBR_H
#define __XRAY_DISK_ANALYZER_EBR_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "mbr.h"

#define SECTOR_SIZE 512

int ebr_probe(FILE* disk, int64_t partition_offset,
              struct mbr* ebr);

#endif
