cmake_minimum_required(VERSION 3.15)
project(thesis_exp2 C)

set(CMAKE_C_STANDARD 99)

set(SOURCES common/debug.c main.c pf.c common/cacheutils.h)

add_definitions(-DEXP_DEBUG)

add_subdirectory(mbedtls)

include_directories(
        common/
)

add_executable(thesis_exp2 ${SOURCES})

target_link_libraries(thesis_exp2 PUBLIC mbedcrypto)