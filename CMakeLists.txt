cmake_minimum_required(VERSION 3.21)
project(mem_alloc C)

set(CMAKE_C_STANDARD 99)

add_executable(mem_alloc
        include/internal/alignment.h
        include/internal/arena.h
        include/internal/binary_tree.h
        include/internal/bit_utils.h
        include/internal/header.h
        src/header.c
        src/arena.c
        src/mem_alloc.c
        src/binary_tree.c
        main.c)
