#ifndef __XRAY_LINKEDLIST_H
#define __XRAY_LINKEDLIST_H

#include <inttypes.h>

struct element;
struct linkedlist;

struct linkedlist* linkedlist_init();
int linkedlist_append(struct linkedlist* ll, void* value, int bytes);
void* linkedlist_get(struct linkedlist* linkedlist, uint64_t i);
int linkedlist_delete(struct linkedlist* linkedlist, struct element* element);
int linkedlist_cleanup(struct linkedlist* linkedlist);

#endif
