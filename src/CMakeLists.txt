list(APPEND CMAKE_REQUIRED_DEFINITIONS)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${MMFD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(mmfd util.c main.c babeld.c neighbour.c vector.c)

target_link_libraries(mmfd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})

set_target_properties(mmfd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall" LINK_FLAGS "")

install(TARGETS mmfd RUNTIME DESTINATION bin)
