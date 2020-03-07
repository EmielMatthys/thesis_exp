cmake_minimum_required(VERSION 3.15)
project(thesis_exp2 C)

set(CMAKE_C_STANDARD 99)

set(SOURCES common/debug.c main.c common/pf.c common/cacheutils.h)

include_directories(
        mbedtls-2.16.5/include/mbedtls
        mbedtls-2.16.5/configs
        common/
)

link_directories(
        mbedtls-2.16.5/library/
)

add_executable(thesis_exp2 ${SOURCES})

target_link_libraries(thesis_exp2 PUBLIC mbedcrypto)