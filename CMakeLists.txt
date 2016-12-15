cmake_minimum_required(VERSION 3.0)

add_executable(dived
  dived.c
  recv_fd.c
  safer.c
)

add_executable(dive
  dive.c
  send_fd.c
  safer.c
)


find_package(PkgConfig)
pkg_search_module(LIBCAP libcap)

include_directories(${CMAKE_BINARY_DIR})
file(WRITE ${CMAKE_BINARY_DIR}/config.h "\n")

if(${LIBCAP_FOUND})
    target_link_libraries(dived ${LIBCAP_LIBRARIES})
    target_include_directories(dived PUBLIC ${LIBCAP_INCLUDE_DIRS})
    target_compile_options(dived PUBLIC ${LIBCAP_CFLAGS_OTHER})
else()
    file(APPEND ${CMAKE_BINARY_DIR}/config.h "#define NO_CAPABILITIES 1\n")
endif()

install(TARGETS dive RUNTIME DESTINATION bin)
install(TARGETS dived RUNTIME DESTINATION bin)

message("If build fails because of something not found about secure bits, pivot_root, signalfd, unshare, setns, CLONE_NEWUSER or execvpe then try usual './configure && make' instead of CMake")
