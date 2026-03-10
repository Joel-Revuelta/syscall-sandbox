cmake_minimum_required(VERSION 3.16)
project(syscall_sandbox C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(sandbox src/sandbox.c)

add_executable(monitor src/monitor.c)
target_include_directories(monitor PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(monitor ${LIBBPF_LIBRARIES} elf z)

add_executable(bpf-bridge src/bpf_bridge.c)
target_include_directories(bpf-bridge PRIVATE ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(bpf-bridge ${LIBBPF_LIBRARIES})

add_executable(syscall_tester src/syscall_tester.c)
