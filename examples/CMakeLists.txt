cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
if(PkgConfig_FOUND )
    MESSAGE(STATUS "============> Found PkgConfig!")
endif(PkgConfig_FOUND )

pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file
if(PROTOBUF_FOUND )
    message(STATUS "============> Found PROTOBUF!")
    message(STATUS "PROTOBUF_INCLUDE_DIRS=${PROTOBUF_INCLUDE_DIRS}")
    message(STATUS "PROTOBUF_LIBRARY_DIRS=${PROTOBUF_LIBRARY_DIRS}")
    message(STATUS "PROTOBUF_LINK_LIBRARIES=${PROTOBUF_LINK_LIBRARIES}")
    message(STATUS "PROTOBUF_LIBRARIES=${PROTOBUF_LIBRARIES}")
endif(PROTOBUF_FOUND )

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    message(STATUS "============> Found OpenSSL!")
    message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OPENSSL_LIBRARIES=${OPENSSL_LIBRARIES}")
endif (OpenSSL_FOUND)

find_package(CryptoBN REQUIRED)
if(CryptoBN_FOUND )
    MESSAGE(STATUS "============> Found CryptoBN!")
    message(STATUS "CryptoBN_DIR = ${CryptoBN_DIR}")
    message(STATUS "CryptoBN_INCLUDE_DIRS = ${CryptoBN_INCLUDE_DIRS}")
    message(STATUS "CryptoBN_LIBRARY_DIR = ${CryptoBN_LIBRARY_DIR}")
    message(STATUS "CryptoBN_LIBRARY = ${CryptoBN_LIBRARY}")
endif(CryptoBN_FOUND )

find_package(CryptoEncode REQUIRED)
if(CryptoEncode_FOUND )
    MESSAGE(STATUS "============> Found CryptoEncode!")
    message(STATUS "CryptoEncode_DIR = ${CryptoEncode_DIR}")
    message(STATUS "CryptoEncode_INCLUDE_DIRS = ${CryptoEncode_INCLUDE_DIRS}")
    message(STATUS "CryptoEncode_LIBRARY_DIR = ${CryptoEncode_LIBRARY_DIR}")
    message(STATUS "CryptoEncode_LIBRARY = ${CryptoEncode_LIBRARY}")
endif(CryptoEncode_FOUND )

find_package(CryptoCurve REQUIRED)
if(CryptoCurve_FOUND )
    MESSAGE(STATUS "============> Found CryptoCurve!")
    message(STATUS "CryptoCurve_DIR = ${CryptoCurve_DIR}")
    message(STATUS "CryptoCurve_INCLUDE_DIRS = ${CryptoCurve_INCLUDE_DIRS}")
    message(STATUS "CryptoCurve_LIBRARY_DIR = ${CryptoCurve_LIBRARY_DIR}")
    message(STATUS "CryptoCurve_LIBRARY = ${CryptoCurve_LIBRARY}")
endif(CryptoCurve_FOUND )

find_package(GTest REQUIRED)
if(GTest_FOUND )
    MESSAGE(STATUS "============> Found GTest!")
    message(STATUS "GTEST_INCLUDE_DIRS=${GTEST_INCLUDE_DIRS}")
    message(STATUS "GTEST_BOTH_LIBRARIES=${GTEST_BOTH_LIBRARIES}")
endif(GTest_FOUND )

add_executable(curve-point-test curve-point-test.cpp)
target_include_directories(curve-point-test PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS}
        )

target_link_libraries( curve-point-test PUBLIC
        CryptoBN
        CryptoCurve
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        ${GTEST_BOTH_LIBRARIES}
        pthread )