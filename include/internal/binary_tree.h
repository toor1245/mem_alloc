#ifndef MEM_ALLOC_BINARY_TREE_H
#define MEM_ALLOC_BINARY_TREE_H

#include <stdint.h>

typedef struct tree_node {
    struct tree_node *parent;
    struct tree_node *left;
    struct tree_node *right;
    uintptr_t address;
    size_t block_size;
} tree_node_t;

typedef struct {
    tree_node_t *root;
} tree_t;

tree_t *tree_from(void *ptr, size_t arena_size);

tree_node_t *tree_node_from(void *ptr, size_t block_size);

void tree_node_push(tree_t *tree, tree_node_t *tree_node);

void tree_traverse_inorder(tree_node_t *tree_node);

tree_node_t *tree_best_fit(tree_t *tree, size_t size);

void tree_node_delete(tree_t *tree, tree_node_t *delete_node);

static void *tree_node_to_payload(tree_node_t *tree_node) {
    return (void *) tree_node;
}

void *tree_node_to_header(tree_node_t *tree_node);

#endif //MEM_ALLOC_BINARY_TREE_H
