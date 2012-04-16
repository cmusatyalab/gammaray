#include "linkedlist.h"

#include <stdlib.h>
#include <string.h>

struct element
{
    struct element* next;
    struct element* prev;
    void* value;
};

struct linkedlist
{
    uint64_t size;
    struct element* head;
    struct element* tail;
    struct element* curr;
};

struct linkedlist* linkedlist_init()
{
    struct linkedlist* ll = malloc(sizeof(struct linkedlist));
    ll->size = 0;
    ll->head = NULL;
    ll->tail = NULL;
    ll->curr = NULL;
    return ll;
}

int linkedlist_append(struct linkedlist* ll, void* value, size_t size)
{
    if (value == NULL || ll == NULL)
        return EXIT_FAILURE;

    struct element* new_e = malloc(sizeof(struct element));

    if (new_e == NULL)
        return EXIT_FAILURE;

    new_e->value = malloc(size);

    if (new_e->value == NULL)
        return EXIT_FAILURE;

    memcpy(new_e->value, value, size);

    if (ll->head == NULL) /* new ll or cleared ll */
    {
        ll->head = new_e;
        ll->tail = new_e;
        ll->curr = new_e;

        new_e->next = NULL;
        new_e->prev = NULL;     
    }
    else if (ll->tail)
    {
        new_e->prev = ll->tail;
        new_e->next = NULL;
        ll->tail->next = new_e;
        ll->tail = new_e;
    }
    else
    {
        return EXIT_FAILURE;
    }

    ll->size++;

    return EXIT_SUCCESS;
}

struct element* __linkedlist_get(struct linkedlist* ll, uint64_t i)
{
    if (ll == NULL)
        return NULL;

    uint64_t counter = 0;
    struct element* e = ll->head;

    for (counter = 0; counter < i && e != NULL; counter++)
    {
        e = e->next;
        if (e == NULL)
            return NULL; 
    }

    return e;
}

void* linkedlist_get(struct linkedlist* ll, uint64_t i)
{
    struct element* e = __linkedlist_get(ll, i);

    if (e == NULL || i > ll->size)
        return NULL;

    return e->value;
}

int __linkedlist_delete(struct linkedlist* ll, struct element* element)
{
    if (ll == NULL || element == NULL)
        return EXIT_FAILURE;

    struct element* next = element->next;
    struct element* prev = element->prev;

    if (prev)
        prev->next = next;

    if (next)
        next->prev = prev;

    if (element == next)
        next = NULL;

    if (element == prev)
        prev = NULL;

    if (element == ll->head)
            ll->head = next;

    if (element == ll->tail)
            ll->tail = prev;

    if (element == ll->curr)
            ll->curr = next;

    element->next = NULL;
    element->prev = NULL;

    free(element->value);
    element->value = NULL;
    free(element);
    ll->size--;
    return EXIT_SUCCESS;
}

int linkedlist_delete(struct linkedlist* ll, uint64_t i)
{
    if (ll == NULL || i > ll->size)
        return EXIT_FAILURE;

    struct element* e = __linkedlist_get(ll, i);

    if (e == NULL)
        return EXIT_FAILURE;

    return __linkedlist_delete(ll, e);
}


struct element* __linkedlist_next(struct linkedlist* ll)
{
    if (ll == NULL || ll->curr == NULL)
        return NULL;

    struct element* e = ll->curr;
    
    ll->curr = e->next;

    return e;
}

int linkedlist_clear(struct linkedlist* ll)
{
    if (ll == NULL)
        return EXIT_FAILURE;

    struct element* e;

    while ((e = __linkedlist_next(ll)))
    {
       __linkedlist_delete(ll, e); 
    }

    ll->head = NULL;
    ll->tail = NULL;
    ll->curr = NULL;
    ll->size = 0;

    return EXIT_SUCCESS;
}

int linkedlist_cleanup(struct linkedlist* ll)
{
    int ret = linkedlist_clear(ll);
    free(ll);
    return ret; 
}

uint64_t linkedlist_size(struct linkedlist* ll)
{
    return ll->size;
}
