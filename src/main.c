#include "mem_alloc.h"

int main() {
    int *arr[200];
    for (int i = 0; i < 200; ++i) {
        arr[i] = (int *) mem_alloc(sizeof(int) * i * 100);
    }
    for (int i = 0; i < 200; ++i) {
        mem_dealloc(arr[i]);
    }
    return 0;
}
