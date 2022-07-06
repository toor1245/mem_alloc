#ifndef MEM_ALLOC_HEADER_H
#define MEM_ALLOC_HEADER_H

#include "stdint.h"
#include "bit_utils.h"
#include "alignment.h"

#define HEADER_BLOCK_SIZE_LSB_SHIFT   0
#define HEADER_BLOCK_SIZE_MSB_SHIFT   59
#define HEADER_STATE_IS_FREE          60
#define HEADER_STATE_IS_FIRST_ARENA   61
#define HEADER_STATE_IS_LAST_ARENA    62

typedef struct {
    size_t size;
    size_t prev;
} header_t;

#define HEADER_ALIGN_SIZE ALIGN_UP(sizeof(header_t))

static inline uint8_t header_is_first_in_arena(header_t *header) {
    return is_bit_set(header->size, HEADER_STATE_IS_FIRST_ARENA);
}

static inline uint8_t header_is_last_in_arena(header_t *header) {
    return is_bit_set(header->size, HEADER_STATE_IS_LAST_ARENA);
}

static inline uint8_t header_is_middle_in_arena(header_t *header) {
    return !header_is_first_in_arena(header) && !header_is_last_in_arena(header);
}

static inline uint8_t header_is_one_in_arena(header_t *header) {
    return header_is_first_in_arena(header) && header_is_last_in_arena(header);
}

static inline size_t header_get_block_size(header_t *header) {
    return extract_bit_range(header->size, HEADER_BLOCK_SIZE_MSB_SHIFT, HEADER_BLOCK_SIZE_LSB_SHIFT);
}

static inline size_t header_get_prev_block_size(header_t *header) {
    return extract_bit_range(header->prev, HEADER_BLOCK_SIZE_MSB_SHIFT, HEADER_BLOCK_SIZE_LSB_SHIFT);
}

static inline uint8_t header_is_free(header_t *header) {
    return is_bit_set(header->size, HEADER_STATE_IS_FREE);
}

static inline header_t *header_get_next_block(header_t *header) {
    if (header_is_last_in_arena(header)) {
        return NULL;
    }
    return (header_t *) ((char *) header + header_get_block_size(header));
}

static inline header_t *header_get_prev_block(header_t *header) {
    if (header_is_first_in_arena(header)) {
        return NULL;
    }
    return (header_t *) ((char *) header - header_get_prev_block_size(header));
}

static inline size_t header_get_bit_states(header_t *header) {
    return extract_bit_range(header->size, 63, 60);
}

static inline void header_set_is_first_arena(header_t *header) {
    set_bit(&header->size, HEADER_STATE_IS_FIRST_ARENA);
}

static inline void header_set_is_last_arena(header_t *header) {
    set_bit(&header->size, HEADER_STATE_IS_LAST_ARENA);
}

static inline void header_set_is_free(header_t *header) {
    set_bit(&header->size, HEADER_STATE_IS_FREE);
}

static inline void header_clear_is_first_arena(header_t *header) {
    clear_bit(&header->size, HEADER_STATE_IS_FIRST_ARENA);
}

static inline void header_clear_is_last_arena(header_t *header) {
    clear_bit(&header->size, HEADER_STATE_IS_LAST_ARENA);
}

static inline void header_clear_is_free(header_t *header) {
    clear_bit(&header->size, HEADER_STATE_IS_FREE);
}

static inline void *header_get_payload(header_t *header) {
    return (void *) ((char *) header + HEADER_ALIGN_SIZE);
}

static inline header_t *header_from_ptr(void *ptr) {
    return (header_t *) ((char *) ptr - HEADER_ALIGN_SIZE);
}

header_t *header_new_one_in_arena_free(void *ptr, size_t size);

header_t *header_new_first_in_arena_free(void *ptr, size_t size);

header_t *header_new_last_in_arena_free(void *ptr, size_t size, size_t prev);

header_t *header_new_middle_in_arena_free(void *ptr, size_t size, size_t prev);

header_t *header_new_one_in_arena_used(void *ptr, size_t size);

header_t *header_new_first_in_arena_used(void *ptr, size_t size);

header_t *header_new_last_in_arena_used(void *ptr, size_t size, size_t prev);

header_t *header_new_middle_in_arena_used(void *ptr, size_t size, size_t prev);

header_t *header_split_block(header_t *header, size_t size, void *tree_block_ptr);

header_t *header_merge_block(header_t *left_header, header_t *right_header);

#endif //MEM_ALLOC_HEADER_H
