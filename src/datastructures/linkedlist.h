#ifndef __XRAY_LINKEDLIST_H
#define __XRAY_LINKEDLIST_H

#include <stddef.h>
#include <inttypes.h>

struct element;
struct linkedlist;

struct linkedlist* linkedlist_init();
int linkedlist_append(struct linkedlist* ll, void* value, size_t size);
void* linkedlist_get(struct linkedlist* linkedlist, uint64_t i);
int linkedlist_delete(struct linkedlist* linkedlist, uint64_t i);
int linkedlist_clear(struct linkedlist* ll);
int linkedlist_cleanup(struct linkedlist* linkedlist);
uint64_t linkedlist_size(struct linkedlist* linkedlist);

#endif
