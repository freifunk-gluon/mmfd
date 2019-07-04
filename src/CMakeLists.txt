list(APPEND CMAKE_REQUIRED_DEFINITIONS)

INCLUDE(FindPkgConfig)
IF(NOT PKG_CONFIG_FOUND)
        MESSAGE(FATAL_ERROR "Error: pkg-config not found on this system")
ENDIF(NOT PKG_CONFIG_FOUND)

set(MMFD_CFLAGS "-Wall -Os -std=gnu11 -D_GNU_SOURCE")

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${MMFD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(mmfd util.c main.c taskqueue.c timespec.c neighbour.c vector.c intercom.c)

target_link_libraries(mmfd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})
set_property(TARGET mmfd PROPERTY COMPILE_FLAGS ${MMFD_CFLAGS})

install(TARGETS mmfd RUNTIME DESTINATION bin)
