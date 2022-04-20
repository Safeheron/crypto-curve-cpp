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

#target_compile_definitions(${TEST_TARGET} PUBLIC MCL_USE_VINT MCL_DONT_USE_XBYAK MCL_VINT_FIXED_BUFFER)
target_compile_options(${TEST_TARGET} PRIVATE ${MCL_COMPILE_OPTIONS})
target_compile_definitions(${TEST_TARGET} PRIVATE MCL_DONT_EXPORT MCL_USE_VINT MCL_VINT_FIXED_BUFFER)

target_link_libraries(${TEST_TARGET}
        ${CMAKE_PROJECT_NAME}
        ${GTEST_BOTH_LIBRARIES}
        pthread
        libmcl.a)

add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET})