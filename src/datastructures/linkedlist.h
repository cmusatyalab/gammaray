#ifndef __XRAY_LINKEDLIST_H
#define __XRAY_LINKEDLIST_H

struct element
{
    struct element* next;
    struct element* prev;
    void* value;
};

struct linkedlist
{
    struct element* head;
    struct element* tail;
    struct element* curr; /* only used when traversing */
};

int init(struct linkedlist* linkedlist);
void* get_head(struct linkedlist* linkedlist);
int push(struct linkedlist* linkedlist);
void* peek(struct linkedlist* linkedlist, void* value);
int destruct(struct linkedlist* linkedlist);

#endif
