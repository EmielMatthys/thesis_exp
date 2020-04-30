add_library(tmeemulator
        src/emulator.c
        )

add_subdirectory(mbedtls)

set_target_properties(tmeemulator PROPERTIES PUBLIC_HEADER include/emulator.h)

target_include_directories(tmeemulator PRIVATE ../common)
target_include_directories(tmeemulator PRIVATE include/)

target_link_libraries(tmeemulator PUBLIC mbedcrypto)