#ifndef __XRAY_DATASTRUCTURES_BST_H
#define __XRAY_DATASTRUCTURES_BST_H

#include <inttypes.h>

struct bst_node
{
    struct bst_node* left_child;
    struct bst_node* right_child;
    uint64_t key;
    void* data;
};

int bst_init(struct bst_node* tree);
int bst_insert(struct bst_node* tree, uint64_t key, void* data);
void* bst_find(struct bst_node* tree, uint64_t key);
int bst_delete(struct bst_node* tree, uint64_t key);

#endif
