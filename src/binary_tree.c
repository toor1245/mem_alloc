#include "internal/binary_tree.h"
#include "internal/alignment.h"
#include "internal/header.h"
#include <stdio.h>
#include <stdlib.h>

#define TREE_ALIGN_SIZE ALIGN_UP(sizeof(tree_t))

tree_node_t *tree_node_from(void *ptr, size_t block_size) {
    tree_node_t *tree_node = (tree_node_t *) ptr;
    tree_node->left = NULL;
    tree_node->right = NULL;
    tree_node->parent = NULL;
    tree_node->block_size = block_size;
    tree_node->address = (uintptr_t) tree_node_to_payload(tree_node);
    return tree_node;
}

tree_t *tree_from(void *ptr, size_t arena_size) {
    tree_t *tree = (tree_t *) ptr;
    void *header_ptr = (char *) ptr + TREE_ALIGN_SIZE;
    header_t *header = header_new_one_in_arena_free(header_ptr, arena_size);
    void *tree_root_node_ptr = align_up_ptr((char *) header + HEADER_ALIGN_SIZE);
    tree->root = tree_node_from(tree_root_node_ptr, arena_size);
    return tree;
}

void tree_node_push(tree_t *tree, tree_node_t *tree_node) {
    if (tree == NULL) {
        printf("method: tree_node_push; info: tree is NULL");
        exit(EXIT_FAILURE);
    }
    if (tree->root == NULL) {
        tree->root = tree_node;
        return;
    }
    tree_node_t *temp_root = tree->root;
    tree_node_t *insert_node = NULL;
    while (temp_root) {
        insert_node = temp_root;
        if (tree_node->block_size < temp_root->block_size) {
            temp_root = temp_root->left;
        } else {
            temp_root = temp_root->right;
        }
    }
    tree_node->parent = insert_node;
    if (insert_node == NULL) {
        tree->root = tree_node;
    } else if (tree_node->block_size < insert_node->block_size) {
        insert_node->left = tree_node;
    } else {
        insert_node->right = tree_node;
    }
}

tree_node_t *tree_best_fit(tree_t *tree, size_t size) {
    if (tree == NULL || tree->root == NULL) {
        return NULL;
    }
    tree_node_t *temp_root_node = tree->root;
    // this tree node holds the last minimum suitable value of tree node.
    tree_node_t *best_fit_node = NULL;
    while (temp_root_node != NULL) {
        if ((best_fit_node == NULL && temp_root_node->block_size > size) ||
            (best_fit_node != NULL && temp_root_node->block_size < best_fit_node->block_size &&
             temp_root_node->block_size > size)) {
            best_fit_node = temp_root_node;
        }
        if (size == temp_root_node->block_size) {
            return temp_root_node;
        }
        if (size < temp_root_node->block_size) {
            temp_root_node = temp_root_node->left;
        } else {
            temp_root_node = temp_root_node->right;
        }
    }
    return best_fit_node;
}

static tree_node_t *tree_node_min(tree_node_t *root) {
    tree_node_t *temp_root_node = root;
    while (temp_root_node->left) {
        temp_root_node = temp_root_node->left;
    }
    return temp_root_node;
}

static void tree_node_transplant(tree_t *tree, tree_node_t *u, tree_node_t *v) {
    if (u->parent == NULL) {
        tree->root = v;
    } else if (u->parent->left == u) {
        u->parent->left = v;
    } else {
        u->parent->right = v;
    }
    if (v != NULL) {
        v->parent = u->parent;
    }
}

void tree_node_delete(tree_t *tree, tree_node_t *delete_node) {
    if (delete_node->left == NULL) {
        tree_node_transplant(tree, delete_node, delete_node->right);
    } else if (delete_node->right == NULL) {
        tree_node_transplant(tree, delete_node, delete_node->left);
    } else {
        tree_node_t *min_node = tree_node_min(delete_node->right);
        if (min_node->parent != delete_node) {
            tree_node_transplant(tree, min_node, min_node->right);
            min_node->right = min_node->right;
            min_node->right->parent = min_node;
        }
        tree_node_transplant(tree, delete_node, min_node);
        min_node->left = delete_node->left;
        min_node->left->parent = min_node;
    }
}

static void print_node_tree(tree_node_t *tree_node) {
    printf("========================================\n");
    printf("node address: %p\n", tree_node);
    printf("left node address: %p\n", tree_node->left);
    printf("right node address: %p\n", tree_node->right);
    printf("block location: %p\n", (void *) tree_node->address);
    printf("block size: %zu\n", tree_node->block_size);
    printf("========================================\n\n");
}

void tree_traverse_inorder(tree_node_t *tree_node) {
    if (!tree_node) return;
    tree_traverse_inorder(tree_node->left);
    print_node_tree(tree_node);
    tree_traverse_inorder(tree_node->right);
}

void *tree_node_to_header(tree_node_t *tree_node) {
    return (void*) ((char *) tree_node - HEADER_ALIGN_SIZE);
}
