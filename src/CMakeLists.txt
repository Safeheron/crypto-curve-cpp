find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)

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

message("CMAKE_PROJECT_NAME= ${CMAKE_PROJECT_NAME}")
add_library(${CMAKE_PROJECT_NAME} SHARED
        crypto-curve/ed25519_ex.c
        crypto-curve/curve.cpp
        crypto-curve/curve_point.cpp
        crypto-curve/curve_point.pb.cc
        crypto-curve/openssl_curve_wrapper.cpp
        crypto-curve/ecdsa.cpp
        crypto-curve/eddsa.cpp
        ${ed25519-donna_SOURCES}
)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        "../third_party"
        ${OPENSSL_INCLUDE_DIR}
        )

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        ${CryptoEncode_INCLUDE_DIRS}
        ${CryptoBN_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME}
        CryptoBN
        CryptoEncode
        ${PROTOBUF_LIBRARIES}
        OpenSSL::Crypto
        -ldl
        )
