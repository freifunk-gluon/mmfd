ADD_DEFINITIONS(-D_GNU_SOURCE)

list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${MMFD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(mmfd main.c genl.c)

target_link_libraries(mmfd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})

set_target_properties(mmfd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall" LINK_FLAGS "")

install(TARGETS mmfd RUNTIME DESTINATION bin)
