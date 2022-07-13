cmake_minimum_required(VERSION 3.21)
project(mem_alloc C)

set(CMAKE_C_STANDARD 99)

include(CheckIncludeFile)
include(CheckSymbolExists)
include(GNUInstallDirs)

macro(setup_include_and_definitions TARGET_NAME)
    target_include_directories(${TARGET_NAME}
            PUBLIC  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
            PUBLIC  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/internal>)
endmacro()

macro(add_headers_and_sources HDRS_LIST_NAME SRCS_LIST_NAME)
    list(APPEND ${HDRS_LIST_NAME} ${PROJECT_SOURCE_DIR}/include/internal/arena.h)
    list(APPEND ${HDRS_LIST_NAME} ${PROJECT_SOURCE_DIR}/include/internal/alignment.h)
    list(APPEND ${HDRS_LIST_NAME} ${PROJECT_SOURCE_DIR}/include/internal/binary_tree.h)
    list(APPEND ${HDRS_LIST_NAME} ${PROJECT_SOURCE_DIR}/include/internal/bit_utils.h)
    list(APPEND ${HDRS_LIST_NAME} ${PROJECT_SOURCE_DIR}/include/internal/header.h)

    list(APPEND ${SRCS_LIST_NAME} ${PROJECT_SOURCE_DIR}/src/arena.c)
    list(APPEND ${SRCS_LIST_NAME} ${PROJECT_SOURCE_DIR}/src/binary_tree.c)
    list(APPEND ${SRCS_LIST_NAME} ${PROJECT_SOURCE_DIR}/src/header.c)
    list(APPEND ${SRCS_LIST_NAME} ${PROJECT_SOURCE_DIR}/src/mem_alloc.c)
endmacro()

set(HEADERS)
set(SOURCES)
add_headers_and_sources(HEADERS SOURCES)
add_library(bi_mem_alloc ${HEADERS} ${SOURCES})
set_target_properties(bi_mem_alloc PROPERTIES PUBLIC_HEADER "${HEADERS}")
setup_include_and_definitions(bi_mem_alloc)
target_link_libraries(bi_mem_alloc PUBLIC ${CMAKE_DL_LIBS})
target_include_directories(bi_mem_alloc
        PUBLIC $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/mem_alloc>
        )
add_library(mem_alloc::bi_mem_alloc ALIAS bi_mem_alloc)

#
# program : mem_alloc demo
#

add_executable(mem_alloc_demo src/main.c)
target_link_libraries(mem_alloc_demo PRIVATE bi_mem_alloc)
add_executable(mem_alloc::mem_alloc_demo ALIAS mem_alloc_demo)
