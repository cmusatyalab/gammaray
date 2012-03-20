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
        {
            return tree->data;
        }

        if (key < tree->key)
        {
            if (tree->left_child == NULL)
            {
                return NULL;
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
                return NULL;
            }
            else
            {
                tree = tree->right_child;
                continue;
            }
        }
    }

    return NULL;
}

void* bst_delete(struct bst_node* tree, uint64_t key)
{
    void* ret = NULL;
    bool replace_left;

    if (tree == NULL)
        return NULL;

    replace_left = ((rand() % 100) < 50);

    //fprintf_light_yellow(stderr, "debug: replace_left is %d\n", replace_left);
    //fprintf_light_yellow(stderr, "debug: deleting with tree=%p key=%"
                                 //PRIu64"\n", tree, key);

    while (1)
    {
        /* found node to delete */
        if (tree->key == key)
        {
            //fprintf_light_red(stderr, "debug: found node to delete\n");
            ret = tree->data;

            if ((replace_left && tree->left_child) ||
               (replace_left == false && tree->right_child == NULL && tree->left_child))
            { /* replace with predecessor */
                //fprintf_light_blue(stderr, "debug: replacing with left node\n");
                tree->key = tree->left_child->key;
                tree->data = tree->left_child->data;

                if (tree->left_child->left_child == NULL &&
                    tree->left_child->right_child == NULL)
                {
                    free(tree->left_child);
                    tree->left_child = NULL;
                }
                else
                {
                    bst_delete(tree->left_child, tree->left_child->key);
                }
            }
            else if (tree->right_child)
            { /* replace with successor */
                //fprintf_light_blue(stderr, "debug: replacing with right node\n");
                tree->key = tree->right_child->key;
                tree->data = tree->right_child->data;

                if (tree->right_child->left_child == NULL &&
                    tree->right_child->right_child == NULL)
                {
                    free(tree->right_child);
                    tree->right_child = NULL;
                }
                else
                {
                    bst_delete(tree->right_child, tree->right_child->key);
                }
            }
            else /* root with no children */
            {
                tree->key = 0;
                tree->data = NULL;
            }
            break;
        }

        if (tree->key < key)
        {
            if (tree->left_child == NULL)
            {
                return NULL;
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
                return NULL;
            }
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
        {
            bst_delete(tree, tree->left_child->key);
        }
        else
        {
            bst_delete(tree, tree->right_child->key);
        }
    }

    free(tree);
    return EXIT_SUCCESS;
}

void bst_print_tree(struct bst_node* tree)
{
    if (tree == NULL)
        return;

    fprintf(stdout, "node[%"PRIu64"]: %p\n", tree->key, tree->data);
    
    if (tree->left_child)
    {
        fprintf(stdout, "\tleft child: ");
        bst_print_tree(tree->left_child);
    }

    if (tree->right_child)
    {
        fprintf(stdout, "\tright child: ");
        bst_print_tree(tree->right_child);
    }
}
