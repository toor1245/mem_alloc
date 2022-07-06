#ifndef MEM_ALLOC_MEM_ALLOC_H
#define MEM_ALLOC_MEM_ALLOC_H

#include <stdint.h>

void *mem_alloc(size_t size);

void mem_dealloc(void *ptr);

void *mem_realloc(void *ptr, size_t size);

#endif //MEM_ALLOC_MEM_ALLOC_H
