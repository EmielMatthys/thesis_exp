cmake_minimum_required(VERSION 3.15)
project(tmeemulator VERSION 1.0.0 DESCRIPTION "emulates total memory encryption")

add_library(tmeemulator SHARED
        src/emulator.c
        )

set_target_properties(tmeemulator PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(tmeemulator PROPERTIES PUBLIC_HEADER include/emulator.h)