#include <assert.h>
#include "../include/mem_alloc.h"
#include "../include/internal/header.h"
#include "../include/internal/binary_tree.h"
#include "../include/internal/arena.h"
#include <string.h>

#define MAX_ALLOC_SIZE ARENA_DEFAULT_SIZE - sizeof(tree_node_t)

static tree_t *block_tree = NULL;

void *mem_alloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    assert(size < MAX_ALLOC_SIZE);
    if (block_tree == NULL) {
        void *arena = arena_default_alloc();
        block_tree = tree_from(arena, ARENA_DEFAULT_SIZE);
    }
    size_t payload_aligned_size = ALIGN_UP(max_bitwise(size, sizeof(tree_node_t)));
    size_t block_size = HEADER_ALIGN_SIZE + payload_aligned_size;
    tree_node_t *found_block = tree_best_fit(block_tree, block_size);
    if (found_block == NULL) {
        void *arena = arena_default_alloc();
        header_t *header = header_new_one_in_arena_used(arena, ARENA_DEFAULT_SIZE);
        header_t *left_header = header_split_block(header, block_size, block_tree);
        return header_get_payload(left_header);
    }
    header_t *header = tree_node_to_header(found_block);
    tree_node_delete(block_tree, found_block);
    header_t *left_header = header_split_block(header, block_size, block_tree);
    return header_get_payload(left_header);
}

void mem_dealloc(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    header_t *header_merge = header_from_ptr(ptr);
    header_t *header_left = header_get_prev_block(header_merge);
    header_t *header_right = header_get_next_block(header_merge);
    if (header_right != NULL && header_is_free(header_right)) {
        tree_node_t *tree_node_to_delete = header_get_payload(header_right);
        tree_node_delete(block_tree, tree_node_to_delete);
        header_merge = header_merge_block(header_merge, header_right);
    }
    if (header_left != NULL && header_is_free(header_left)) {
        tree_node_t *tree_node_to_delete = header_get_payload(header_left);
        tree_node_delete(block_tree, tree_node_to_delete);
        header_merge_block(header_left, header_merge);
    }
    if (header_is_one_in_arena(header_merge)) {
        arena_default_free(ptr);
        return;
    }
    tree_node_t *tree_node_to_push = tree_node_from(header_merge, header_get_block_size(header_merge));
    tree_node_push(block_tree, tree_node_to_push);
}

void *mem_realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return mem_alloc(size);
    }
    if (size == 0) {
        mem_dealloc(ptr);
        return NULL;
    }
    header_t *header = header_from_ptr(ptr);
    size_t aligned_size = ALIGN_UP(max_bitwise(size, sizeof(tree_node_t)));
    if (header->size == aligned_size) {
        return ptr;
    }
    if (header->size < aligned_size) {
        header_t *left_header = header_split_block(header, aligned_size, block_tree);
        return header_get_payload(left_header);
    }
    header_t *right_header = header_get_next_block(header);
    header_t *left_header = header_get_prev_block(header);
    if (right_header != NULL && header_is_free(right_header)) {
        header_t *merge_block = header_merge_block(header, right_header);
        header = header_split_block(merge_block, aligned_size, block_tree);
    }
    if (left_header != NULL && header_is_free(left_header)) {
        header_t *merge_block = header_merge_block(header, left_header);
        header = header_split_block(merge_block, aligned_size, block_tree);
    }
    void* realloc_ptr = mem_alloc(size);
    if (realloc_ptr != NULL) {
        memcpy(realloc_ptr, ptr, header->size - HEADER_ALIGN_SIZE);
        mem_dealloc(ptr);
    }
    return realloc_ptr;
}
