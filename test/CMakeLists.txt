cmake_minimum_required(VERSION 3.10)
project(test)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

include_directories("../src")

add_executable(curve-point-test curve-point-test.cpp)
target_link_libraries( curve-point-test
        CryptoCurve
        ${GTEST_BOTH_LIBRARIES}
        pthread )
add_test(NAME test-curve-point COMMAND curve-point-test)