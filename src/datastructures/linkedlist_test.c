#include "linkedlist.h"

#include "color.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    struct linkedlist* ll = linkedlist_init();
    int i, *val;

    for (i = 0; i < 10; i++)
    {
        linkedlist_append(ll, &i, sizeof(int));
        fprintf_light_blue(stdout, "appended: %d\n", i);
    }

    for (i = 0; i < 10; i++)
    {
        if ((val = linkedlist_get(ll, i)))
            fprintf_light_green(stdout, "element[%d] = %d\n", i, *val);
    }

    for (i = 10; i >= 0; i--)
    {
        if ((val = linkedlist_get(ll, i)))
            fprintf_light_green(stdout, "element[%d] = %d\n", i, *val);
    }

    linkedlist_clear(ll);

    for (i = 0; i < 10; i++)
    {
        linkedlist_append(ll, &i, sizeof(int));
        fprintf_light_blue(stdout, "appended: %d\n", i);
    }

    linkedlist_delete(ll, 5);
    linkedlist_delete(ll, 3);
    linkedlist_delete(ll, 7);
    linkedlist_delete(ll, 0);

    for (i = 10; i >= 0; i--)
    {
        if ((val = linkedlist_get(ll, i)))
            fprintf_light_green(stdout, "element[%d] = %d\n", i, *val);
    }

    linkedlist_cleanup(ll);

    return EXIT_SUCCESS;
}
