#include <assert.h>
#include "internal/header.h"
#include "internal/binary_tree.h"

#include "header_states.inl"

static header_t *header_new(void *ptr, size_t size, size_t prev, size_t state) {
    header_t *new_header = (header_t *) ptr;
    new_header->size = HEADER_CREATE_SIZE(size, state);
    new_header->prev = prev;
    return new_header;
}

header_t *header_new_one_in_arena_free(void *ptr, size_t size) {
    return header_new(ptr, size, HEADER_PREVIOUS_SIZE_EMPTY, HEADER_STATE_ONE_IN_ARENA_FREE);
}

header_t *header_new_first_in_arena_free(void *ptr, size_t size) {
    return header_new(ptr, size, HEADER_PREVIOUS_SIZE_EMPTY, HEADER_STATE_FIRST_IN_ARENA_FREE);
}

header_t *header_new_middle_in_arena_free(void *ptr, size_t size, size_t prev) {
    return header_new(ptr, size, prev, HEADER_STATE_MIDDLE_IN_ARENA_FREE);
}

header_t *header_new_last_in_arena_free(void *ptr, size_t size, size_t prev) {
    return header_new(ptr, size, prev, HEADER_STATE_LAST_IN_ARENA_FREE);
}

header_t *header_new_one_in_arena_used(void *ptr, size_t size) {
    return header_new(ptr, size, HEADER_PREVIOUS_SIZE_EMPTY, HEADER_STATE_ONE_IN_ARENA_USED);
}

header_t *header_new_first_in_arena_used(void *ptr, size_t size) {
    return header_new(ptr, size, HEADER_PREVIOUS_SIZE_EMPTY, HEADER_STATE_FIRST_IN_ARENA_USED);
}

header_t *header_new_last_in_arena_used(void *ptr, size_t size, size_t prev) {
    return header_new(ptr, size, prev, HEADER_STATE_MIDDLE_IN_ARENA_USED);
}

header_t *header_new_middle_in_arena_used(void *ptr, size_t size, size_t prev) {
    return header_new(ptr, size, prev, HEADER_STATE_LAST_IN_ARENA_USED);
}

typedef header_t *(*create_left_header_f)(void *, size_t size);

typedef header_t *(*create_left_header_f_with_prev)(void *, size_t size, size_t prev);

typedef header_t *(*create_right_header_f)(void *, size_t size, size_t prev);

typedef struct {
    void *current_header;
    size_t left_block_size;
    size_t right_block_size;
    tree_t *tree_block;
} header_split;

typedef struct {
    header_split *header_split;
    create_left_header_f create_left_header;
} header_split_fallback;

typedef struct {
    header_split *header_split;
    create_left_header_f_with_prev create_left_header_with_prev;
} header_split_fallback_with_prev;

static void header_separate_right_block_and_push(header_split *header_split,
                                                 create_right_header_f create_right_header) {
    size_t left_size = ((header_t *) header_split->current_header)->size;
    size_t right_block_size = header_split->right_block_size;
    void *right_ptr = (void *) ((char *) header_split->current_header + header_split->left_block_size);
    header_t *right_block = create_right_header(right_ptr, right_block_size, left_size);
    tree_node_t *tree_node = tree_node_from(header_get_payload(right_block), right_block_size);
    tree_node_push(header_split->tree_block, tree_node);
}

static header_t *header_split_block_fallback(header_split_fallback *header_split_fallback,
                                             create_right_header_f right_header) {
    header_t *header = (header_t *) header_split_fallback->header_split->current_header;
    size_t left_size = header_split_fallback->header_split->left_block_size;
    header_t *left_block = header_split_fallback->create_left_header(header, left_size);
    header_separate_right_block_and_push(header_split_fallback->header_split, right_header);
    return left_block;
}

static header_t *header_split_block_fallback_with_prev(header_split_fallback_with_prev *header_split_fallback,
                                                       create_right_header_f create_right_header) {
    header_t *header = (header_t *) header_split_fallback->header_split->current_header;
    size_t left_size = header_split_fallback->header_split->left_block_size;
    header_t *left_block = header_split_fallback->create_left_header_with_prev(header, left_size, header->prev);
    header_separate_right_block_and_push(header_split_fallback->header_split, create_right_header);
    return left_block;
}

header_t *header_split_block(header_t *header, size_t size, void *tree_block_ptr) {
    assert(header_get_block_size(header) > size);
    header_split split = {
            .tree_block = (tree_t *) tree_block_ptr,
            .current_header = header,
            .left_block_size = size,
            .right_block_size = header_get_block_size(header) - size,
    };
    if (header_is_one_in_arena(header)) {
        header_split_fallback split_fallback = {
                .header_split = &split,
                .create_left_header = header_new_first_in_arena_used
        };
        return header_split_block_fallback(&split_fallback, header_new_last_in_arena_free);
    }
    if (header_is_first_in_arena(header)) {
        header_split_fallback split_fallback = {
                .header_split = &split,
                .create_left_header = header_new_first_in_arena_used
        };
        return header_split_block_fallback(&split_fallback, header_new_middle_in_arena_free);
    }
    if (header_is_last_in_arena(header)) {
        header_split_fallback_with_prev split_fallback = {
                .header_split = &split,
                .create_left_header_with_prev = header_new_middle_in_arena_used
        };
        return header_split_block_fallback_with_prev(&split_fallback, header_new_last_in_arena_free);
    }
    // header is middle in arena.
    header_split_fallback_with_prev split_fallback = {
            .header_split = &split,
            .create_left_header_with_prev = header_new_middle_in_arena_used
    };
    return header_split_block_fallback_with_prev(&split_fallback, header_new_middle_in_arena_free);
}

header_t *header_merge_block(header_t *left_header, header_t *right_header) {
    size_t bit_states = header_get_bit_states(left_header);
    size_t block_size = header_get_block_size(left_header) + header_get_block_size(right_header);
    if (!header_is_last_in_arena(right_header)) {
        header_t *next_right = header_get_next_block(right_header);
        next_right->prev = HEADER_CREATE_SIZE(block_size, bit_states);
    } else {
        header_set_is_last_arena(left_header);
    }
    return header_new(left_header, block_size, left_header->prev, bit_states);
}
