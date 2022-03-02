cmake_minimum_required(VERSION 3.10)
project(CryptoCurve)

set(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable")

find_package(PkgConfig REQUIRED)
if (PkgConfig_FOUND)
    MESSAGE(STATUS "============> Found PkgConfig_FOUND!")
endif (PkgConfig_FOUND)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    MESSAGE(STATUS "============> Found OpenSSL!")
    message(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
endif (OpenSSL_FOUND)
include_directories(${OPENSSL_CURVE_WRAPPER_H})

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


include_directories("../third_party")

file(GLOB ed25519-donna_SOURCES
        ../third_party/ed25519-donna/curve25519-donna-32bit.c
        ../third_party/ed25519-donna/curve25519-donna-helpers.c
        ../third_party/ed25519-donna/curve25519-donna-scalarmult-base.c
        ../third_party/ed25519-donna/ed25519.c
        ../third_party/ed25519-donna/ed25519-donna-32bit-tables.c
        ../third_party/ed25519-donna/ed25519-donna-basepoint-table.c
        ../third_party/ed25519-donna/ed25519-donna-impl-base.c
        ../third_party/ed25519-donna/ed25519-donna-memzero.c
#        ../third_party/ed25519-donna/ed25519-sha3.c
#        ../third_party/ed25519-donna/ed25519-keccak.c
        ../third_party/ed25519-donna/modm-donna-32bit.c
)

add_library(${PROJECT_NAME} SHARED
        crypto-curve/curve.cpp
        crypto-curve/curve_point.cpp
        crypto-curve/curve_point.pb.cc
        crypto-curve/ed25519_ex.c
        crypto-curve/openssl_curve_wrapper.cpp
        ${ed25519-donna_SOURCES}
)

target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoEncode_INCLUDE_DIRS}
        ${CryptoBN_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${PROTOBUF_LIBRARIES}
        CryptoBN
        CryptoEncode
        OpenSSL::Crypto
        -ldl
        )
