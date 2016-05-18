cmake_minimum_required(VERSION 2.8.3)
project(MMFD C)

INCLUDE(FindPkgConfig)
IF(NOT PKG_CONFIG_FOUND)
	MESSAGE(FATAL_ERROR "Error: pkg-config not found on this system")
ENDIF(NOT PKG_CONFIG_FOUND)

set(CMAKE_MODULE_PATH ${MMFD_SOURCE_DIR})

add_subdirectory(src)
