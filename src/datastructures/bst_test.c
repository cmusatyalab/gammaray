#include <stdlib.h>

#include "color.h"
#include "bst.h"

int test_bst_init(struct bst_node** tree, uint64_t key, void* data)
{
    if ((*tree = bst_init(key, data)) == NULL)
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
    int i;
    for (i = 0; i < num; i++)
    {
        if (bst_find(tree, keys[i]) != values[i])
        {
            fprintf_light_red(stderr, "test_bst_find failed values: i=%d "
                                       "tree=%p key=%"PRIu64" value=%p bst_find=%p\n",
                                       i, tree, keys[i], values[i],
                                       bst_find(tree, keys[i]));
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int test_bst_delete(struct bst_node* tree, uint64_t keys[], void* values[],
                    int num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        if (bst_delete(tree, NULL, keys[i]) != values[i])
        {
            fprintf_light_red(stderr, "test_bst_delete failed values: i=%d "
                                       "tree=%p key=%"PRIu64" value=%p bst_find=%p\n",
                                       i, tree, keys[i], values[i],
                                       bst_delete(tree, NULL, keys[i]));
            return EXIT_FAILURE;
        }
        bst_print_tree(tree, 0);
    }
    return EXIT_SUCCESS;
}

int test_bst_destruct(struct bst_node* tree)
{
    return bst_destruct(tree);
}

int main(int argc, char* argv[])
{
    struct bst_node* tree;
    uint64_t keys[] = {10,7,4,3,6,5,8,2,9,0,1};
    void*  values[] = {(void*) 1, (void*) 1, (void*) 1, (void*) 1, (void*) 1,
                       (void*) 1, (void*) 1, (void*) 1, (void*) 1, (void*) 1,
                       (void*) 1};
    int total = 11;

    fprintf_light_cyan(stdout, "bst test harness running.\n");

    /* init test */
    if (test_bst_init(&tree, 0, NULL))
    {
        fprintf_light_red(stderr, "bst_init test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_init test passed.\n");
    }

    /* insert test */
    if (test_bst_insert(tree, keys, values, total))
    {
        fprintf_light_red(stderr, "bst_insert test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_insert test passed.\n");
    }

    bst_print_tree(tree, 0);

    uint64_t keys2[] = {0,1,2,3,4,5,6,7,8,9,10};

    /* find test */
    if (test_bst_find(tree, keys2, values, total))
    {
        fprintf_light_red(stderr, "bst_find test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_find test passed.\n");
    }

    /* delete test */
    if (test_bst_delete(tree, keys2, values, total))
    {
        fprintf_light_red(stderr, "bst_delete test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_delete test passed.\n");
    }

    /* destruct test */
    if (test_bst_destruct(tree))
    {
        fprintf_light_red(stderr, "bst_destruct test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_destruct test passed.\n");
    }    

    /* init test */
    if (test_bst_init(&tree, 0, NULL))
    {
        fprintf_light_red(stderr, "bst_init test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_init test passed.\n");
    }

    /* insert test */
    if (test_bst_insert(tree, keys, values, total))
    {
        fprintf_light_red(stderr, "bst_insert test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_insert test passed.\n");
    }

    bst_print_tree(tree, 0);

    /* destruct test */
    if (test_bst_destruct(tree))
    {
        fprintf_light_red(stderr, "bst_destruct test failed.\n");
        return EXIT_FAILURE;
    }
    else
    {
        fprintf_light_green(stdout, "bst_destruct test passed.\n");
    }    

    return EXIT_SUCCESS;
}
