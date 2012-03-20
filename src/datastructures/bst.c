#include <stdlib.h>

#include "../disk_analyzer/color.h"
#include "bst.h"

int bst_init(struct bst_node* tree)
{
    if (tree == NULL)
        return EXIT_FAILURE;

    tree->left_child = NULL;
    tree->right_child = NULL;
    tree->key = 0;
    tree->data = NULL;

    return EXIT_SUCCESS;
}

int bst_insert(struct bst_node* tree, uint64_t key, void* data)
{
    return EXIT_SUCCESS;
}

void* bst_find(struct bst_node* tree, uint64_t key)
{
    return NULL;
}

int bst_delete(struct bst_node* tree, uint64_t key)
{
    return EXIT_SUCCESS;
}
