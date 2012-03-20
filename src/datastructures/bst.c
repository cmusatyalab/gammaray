#include <stdbool.h>
#include <stdlib.h>

#include "../disk_analyzer/color.h"
#include "bst.h"

struct bst_node* bst_init(uint64_t key, void* data)
{
    struct bst_node* tree = (struct bst_node*) malloc(sizeof(struct bst_node));

    if (tree == NULL)
        return NULL;

    tree->left_child = NULL;
    tree->right_child = NULL;
    tree->key = key;
    tree->data = data;

    return tree;
}

int bst_insert(struct bst_node* tree, uint64_t key, void* data)
{
    if (tree == NULL)
        return EXIT_FAILURE;

    struct bst_node* new_node;

    if ((new_node = bst_init(key, data)) == NULL)
        return EXIT_FAILURE;

    while (1)
    {
        if (tree->key == key)
        {
            free(new_node);
            tree->data = data;
            break;
        }

        if (key < tree->key)
        {
            if (tree->left_child == NULL)
            {
                 tree->left_child = new_node;
                 break;
            }
            else
            {
                tree = tree->left_child;
                continue;
            }
        }
        else
        {
            if (tree->right_child == NULL)
            {
                tree->right_child = new_node;
                break;
            }
            else
            {
                tree = tree->right_child;
                continue;
            }
        }
    }

    return EXIT_SUCCESS;
}

void* bst_find(struct bst_node* tree, uint64_t key)
{
    if (tree == NULL)
        return NULL;

    while (1)
    {
        if (tree->key == key)
            return tree->data;

        if (key < tree->key)
        {
            if (tree->left_child == NULL)
                return NULL;
            else
            {
                tree = tree->left_child;
                continue;
            }
        }
        else
        {
            if (tree->right_child == NULL)
                return NULL;
            else
            {
                tree = tree->right_child;
                continue;
            }
        }
    }

    return NULL;
}

/* internal helper to find minimum falue in a BST */
struct bst_node* __bst_find_min(struct bst_node* tree)
{
    if (tree == NULL || tree->left_child == NULL)
        return tree;

    while (tree->left_child != NULL)
        tree = tree->left_child;

    return tree;
}

/* internal helper to find minimum falue in a BST */
struct bst_node* __bst_find_max(struct bst_node* tree)
{
    if (tree == NULL || tree->right_child == NULL)
        return tree;

    while (tree->right_child != NULL)
        tree = tree->right_child;

    return tree;
}

/* deletes a node, requires knowledge of parent; pass NULL for a root node */
void* bst_delete(struct bst_node* tree, struct bst_node* parent, uint64_t key)
{
    void* ret = NULL;
    bool replace_left;
    struct bst_node* replacement = NULL;

    if (tree == NULL)
        return NULL;

    replace_left = ((rand() % 100) < 50);

    while (1)
    {
        /* found node to delete */
        if (tree->key == key)
        {
            ret = tree->data;

            if ((replace_left && tree->left_child) ||
               (replace_left == false && tree->right_child == NULL && tree->left_child))
            { /* replace with in-order predecessor */
                replacement = __bst_find_max(tree->left_child);
                tree->key = replacement->key;
                tree->data = replacement->data;
                bst_delete(tree->left_child, tree, replacement->key);
            }
            else if (tree->right_child)
            { /* replace with in-order successor */
                replacement = __bst_find_min(tree->right_child);
                tree->key = replacement->key;
                tree->data = replacement->data;
                bst_delete(tree->right_child, tree, replacement->key);
            }
            else /* leaf or root no children */
            {
                if (parent && parent != tree) /* leaf */
                {
                    if (parent->left_child == tree)
                        parent->left_child = NULL;
                    else
                        parent->right_child = NULL;
                    free(tree);
                    break;
                }

                tree->key = 0;
                tree->data = NULL;
            }
            break;
        }

        parent = tree;

        /* still searching for node to delete */
        if (key < tree->key)
        {
            if (tree->left_child == NULL)
                return NULL;
            else
            {
                tree = tree->left_child;
                continue;
            }
        }
        else
        {
            if (tree->right_child == NULL)
                return NULL;
            else
            {
                tree = tree->right_child;
                continue;
            }
        }
    }

    return ret;
}

int bst_destruct(struct bst_node* tree)
{
    if (tree == NULL)
        return EXIT_FAILURE;

    while (tree->left_child || tree->right_child)
    {
        if (tree->left_child)
            bst_delete(tree, NULL, tree->left_child->key);
        else
            bst_delete(tree, NULL, tree->right_child->key);
    }

    free(tree); /* bst_delete doesn't free root nodes */
    return EXIT_SUCCESS;
}

void bst_print_tree(struct bst_node* tree, uint64_t parent)
{
    if (tree == NULL)
        return;

    fprintf(stdout, "node[%"PRIu64", p=%"PRIu64"]: %p\n", tree->key, parent,
                                                          tree->data);
    
    if (tree->left_child)
    {
        fprintf(stdout, "left child: ");
        bst_print_tree(tree->left_child, tree->key);
    }

    if (tree->right_child)
    {
        fprintf(stdout, "right child: ");
        bst_print_tree(tree->right_child, tree->key);
    }
}
