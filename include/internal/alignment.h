#ifndef MEM_ALLOC_ALIGNMENT_H
#define MEM_ALLOC_ALIGNMENT_H

#include <stdint.h>
#include "bit_utils.h"

#define MEM_ALLOC_ALIGNMENT 16

#define ALIGN_UP(size) ((size + MEM_ALLOC_ALIGNMENT - 1) & ~(MEM_ALLOC_ALIGNMENT - 1))

static inline void *align_up_ptr(void *ptr) {
    return (void *) ALIGN_UP((uintptr_t) ptr);
}

#endif // MEM_ALLOC_ALIGNMENT_H
