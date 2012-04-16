#include "linkedlist.h"

#include "util.c"

#include <stdio.h>
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
    struct element* head;
    struct element* tail;
    struct element* curr;
};

struct linkedlist* linkedlist_init()
{
    struct linkedlist* ll = malloc(sizeof(struct linkedlist));
    ll->head = NULL;
    ll->tail = NULL;
    ll->curr = NULL;
    return ll;
}

int linkedlist_append(struct linkedlist* ll, void* value, int bytes)
{
    if (value == NULL || ll == NULL)
        return EXIT_FAILURE;

    struct element* new_e = malloc(sizeof(struct element));

    if (new_e == NULL)
        return EXIT_FAILURE;

    new_e->value = malloc(bytes);

    if (new_e->value == NULL)
        return EXIT_FAILURE;

    memcpy(new_e->value, value, bytes);

    if (ll->head == NULL) /* new ll or cleared ll */
    {
        ll->head = new_e;
        ll->tail = new_e;
        ll->curr = new_e;

        new_e->next = new_e;
        new_e->prev = new_e;        
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

    return EXIT_SUCCESS;
}

void* linkedlist_get(struct linkedlist* ll, uint64_t i)
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

    fprintf_light_red(stderr, "_get returning e=%p val=%p real=%d i=%"PRIu64"\n",
                              e, e->value, *((int*) (e->value)), i);
    return e->value;
}

int linkedlist_delete(struct linkedlist* ll, struct element* element)
{
    if (ll == NULL || element == NULL)
        return EXIT_FAILURE;

    struct element* next = element->next;
    struct element* prev = element->prev;

    if (prev)
        prev->next = next;

    if (next)
        next->prev = prev;

    if (element == ll->head)
            ll->head = next;

    if (element == ll->tail)
            ll->tail = prev;

    if (element == ll->curr)
            ll->curr = next;

    element->next = NULL;
    element->prev = NULL;
    element->value = NULL;

    free(element->value);
    free(element);
    return EXIT_SUCCESS;
}

struct element* linkedlist_next(struct linkedlist* ll)
{
    if (ll == NULL || ll->curr == NULL)
        return NULL;

    struct element* e = ll->curr;
    
    ll->curr = e->next;

    return e;
}

int linkedlist_cleanup(struct linkedlist* ll)
{
    if (ll == NULL)
        return EXIT_FAILURE;

    struct element* e;

    while ((e = linkedlist_next(ll)))
    {
       linkedlist_delete(ll, e); 
    }

    free(ll);

    return EXIT_SUCCESS;
}
