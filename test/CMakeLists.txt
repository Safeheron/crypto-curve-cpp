find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories(
        ${GTEST_INCLUDE_DIRS}
        "../src"
        )

option(ENABLE_ASSEMBLE "Enable assemble" OFF)
if (NOT ${ENABLE_ASSEMBLE})
        link_libraries(CryptoCurve
                ${GTEST_BOTH_LIBRARIES}
                pthread )
else()
        link_libraries(${CMAKE_PROJECT_NAME}
                ${GTEST_BOTH_LIBRARIES}
                pthread )
endif()


add_executable(curve-point-test curve-point-test.cpp)
add_test(NAME curve-point-test COMMAND curve-point-test)