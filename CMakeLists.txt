cmake_minimum_required(VERSION 2.8.3)
project(MMFD C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(deps)

set(CMAKE_MODULE_PATH ${MMFD_SOURCE_DIR})

add_subdirectory(src)
