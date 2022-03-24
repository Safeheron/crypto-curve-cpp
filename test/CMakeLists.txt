find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

set(TEST_TARGET curve-point-test)

add_executable(${TEST_TARGET}
        curve-point-test.cpp
        )

target_include_directories(${TEST_TARGET} PRIVATE
        ${GTEST_INCLUDE_DIRS}
        "../src"
        )

target_link_libraries(${TEST_TARGET}
        ${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread )

add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET})