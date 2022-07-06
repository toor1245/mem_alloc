#ifndef MEM_ALLOC_ARENA_H
#define MEM_ALLOC_ARENA_H

#define PAGES_SIZE_KB           4096
#define ARENA_DEFAULT_SIZE      64 * PAGES_SIZE_KB

void *arena_default_alloc();

void arena_default_free(void* ptr);

#endif //MEM_ALLOC_ARENA_H
