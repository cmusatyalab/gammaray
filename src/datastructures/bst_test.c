#include <stdlib.h>

#include "../disk_analyzer/color.h"
#include "bst.h"

int test_bst_init(struct bst_node* tree)
{
    if (bst_init(tree))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int test_bst_insert(struct bst_node* tree, uint64_t keys[], void* values[],
                    int num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        if (bst_insert(tree, keys[i], values[i]))
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int test_bst_find(struct bst_node* tree, uint64_t keys[], void* values[],
                  int num)
{
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[])
{
    struct bst_node tree;
    uint64_t keys[] = {0,1,2,3,4,5,6,7,8,9,10};
    void*  values[] = {(void*) 1, (void*) 1, (void*) 1, (void*) 1, (void*) 1,
                       (void*) 1, (void*) 1, (void*) 1, (void*) 1, (void*) 1,
                       (void*) 1};
    int total = 11;

    fprintf_light_cyan(stdout, "bst test harness running.\n");

    /* init test */
    if (test_bst_init(&tree))
    {
        fprintf_light_red(stderr, "bst_init test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_init test passed.\n");
    }

    /* insert test */
    if (test_bst_insert(&tree, keys, values, total))
    {
        fprintf_light_red(stderr, "bst_insert test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_insert test passed.\n");
    }

    /* find test */
    /*if (test_bst_insert(&tree, keys, values, total))
    {
        fprintf_light_red(stderr, "bst_insert test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_insert test passed.\n");
    }*/

    return EXIT_SUCCESS;
}
