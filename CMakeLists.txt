cmake_minimum_required(VERSION 3.15)
project(thesis_exp C)

set(CMAKE_C_STANDARD 99)

#set(SOURCES main.c)

add_definitions(-DEXP_DEBUG)

add_subdirectory(tme)
add_subdirectory(attack)

include_directories(
        common/
)

#add_executable(thesis_exp ${SOURCES})
target_include_directories(simple_attack PRIVATE .)
target_link_libraries(simple_attack PUBLIC tmeemulator)