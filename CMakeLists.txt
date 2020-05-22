cmake_minimum_required(VERSION 3.17)

project(MKhook C)

set(EXECUTABLE_PATH /usr/bin)

set(CMAKE_C_COMPILER ${EXECUTABLE_PATH}/gcc)
set(CMAKE_ASM_COMPILER ${EXECUTABLE_PATH}/nasm)
set(CMAKE_LINKER ${EXECUTABLE_PATH}/ld)
set(CMAKE_AR ${EXECUTABLE_PATH}/ar)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

enable_testing()
set(TESTS_TARGETS "" CACHE INTERNAL "targets to run with ctest")
function(add_to_tests target command)
	set(TESTS_TARGETS ${TESTS_TARGETS} ${command} CACHE INTERNAL "TESTS_TARGETS")
	add_test(NAME ${target} COMMAND ${command})
endfunction(add_to_tests)

set(CMAKE_C_FLAGS_DEBUG
	"-g -Wall -Wextra -Werror -Wno-unused-function")
set(CMAKE_C_FLAGS "-Os -fstack-protector")

include_directories(.)
include_directories(Libraries)

add_subdirectory(Libraries)
add_subdirectory(src)

add_custom_target(do_tests ALL
					COMMAND ctest --output-on-failure
					DEPENDS ${TESTS_TARGETS})
