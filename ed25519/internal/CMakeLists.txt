cmake_minimum_required(VERSION 3.14)
PROJECT(ed25519)

include_directories(./)
add_library(${PROJECT_NAME} STATIC ed25519.c)

link_libraries(crypto)

add_executable(test test.c ed25519.c modm-donna-64bit.h)
target_compile_options(test PUBLIC -DED25519_TEST)
add_executable(test_internal test-internals.c)