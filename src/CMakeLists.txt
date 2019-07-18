list(APPEND CMAKE_REQUIRED_DEFINITIONS)

INCLUDE(FindPkgConfig)
IF(NOT PKG_CONFIG_FOUND)
        MESSAGE(FATAL_ERROR "Error: pkg-config not found on this system")
ENDIF(NOT PKG_CONFIG_FOUND)

set(MMFD_CFLAGS "-Wall -Os -std=gnu11 -D_GNU_SOURCE")
pkg_check_modules(_JSON_C json-c)

find_path(JSON_C_INCLUDE_DIR NAMES json-c/json.h HINTS ${_JSON_C_INCLUDE_DIRS})
find_library(JSON_C_LIBRARIES NAMES json-c HINTS ${_JSON_C_LIBRARY_DIRS})

set(JSON_C_CFLAGS_OTHER "${_JSON_C_CFLAGS_OTHER}" CACHE STRING "Additional compiler flags for json-c")
set(JSON_C_LDFLAGS_OTHER "${_JSON_C_LDFLAGS_OTHER}" CACHE STRING "Additional linker flags for json-c")


include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${MMFD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(mmfd util.c main.c taskqueue.c timespec.c neighbour.c vector.c intercom.c socket.c)

find_package_handle_standard_args(JSON_C REQUIRED_VARS JSON_C_LIBRARIES JSON_C_INCLUDE_DIR)
mark_as_advanced(JSON_C_INCLUDE_DIR JSON_C_LIBRARIES JSON_C_CFLAGS_OTHER JSON_C_LDFLAGS_OTHER)

target_link_libraries(mmfd ${JSON_C_LIBRARIES} ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})
set_property(TARGET mmfd PROPERTY COMPILE_FLAGS  ${MMFD_CFLAGS})

install(TARGETS mmfd RUNTIME DESTINATION bin)
