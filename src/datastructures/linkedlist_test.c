#include "linkedlist.h"

#include "color.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
    struct linkedlist* ll = linkedlist_init();
    int i;

    for (i = 0; i < 10; i++)
    {
        linkedlist_append(ll, &i, sizeof(int));
        fprintf_light_blue(stdout, "appended: %d\n", i);
    }

    for (i = 0; i < 10; i++)
    {
        fprintf_light_green(stdout, "element[%d] = %d\n", i,
                                     * ((int*) linkedlist_get(ll, i)));
    }

    linkedlist_cleanup(ll);
    return EXIT_SUCCESS;
}
