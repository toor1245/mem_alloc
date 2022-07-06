#include <assert.h>
#include "Windows.h"
#include "../include/internal/arena.h"

void *arena_default_alloc() {
    void *arena = (void *) VirtualAlloc(NULL, ARENA_DEFAULT_SIZE, MEM_COMMIT, PAGE_READWRITE);
    assert(arena != NULL);
    return arena;
}

void arena_default_free(void* ptr) {
    BOOL is_free = VirtualFree((LPVOID) ptr, 0, MEM_RELEASE);
    assert(is_free == TRUE);
}
