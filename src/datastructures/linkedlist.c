#include "linkedlist.h"

void* get_head(struct linkedlist* linkedlist)
{
    return linkedlist->head;
}

void* peek(struct linkedlist* linkedlist)
{
   return linkedlist->curr++; 
}

int push(struct linkedlist* linkedlist)
{
    /* replace head, update head and tail *
     * update head next */ 

    return EXIT_SUCESS;
}

int delete_curr()
{
    /* update head and tail accordingly */
    /* update next and prev guys accordingly */
}
