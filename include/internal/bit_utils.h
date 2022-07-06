#ifndef MEM_ALLOC_BIT_UTILS_H
#define MEM_ALLOC_BIT_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

static inline uint8_t is_bit_set(const size_t reg, const size_t bit) {
    return (uint8_t) ((reg >> bit) & 0x01);
}

static inline void set_bit(size_t *reg, const size_t bit) {
    *reg |= (1UL << bit);
}

static inline void clear_bit(size_t *reg, const size_t bit) {
    *reg &= ~(1UL << bit);
}

static inline size_t max_bitwise(size_t left, size_t right) {
    // left & ((right - left) >> 63) | right & (~(right - left) >> 63)
    return max(left, right);
}

static inline uint64_t extract_bit_range(size_t reg, size_t msb, size_t lsb) {
    const uint64_t bits = msb - lsb + 1ULL;
    const uint64_t mask = (1ULL << bits) - 1ULL;
    assert(msb >= lsb);
    return (reg >> lsb) & mask;
}

#endif //MEM_ALLOC_BIT_UTILS_H
