/*
 * Copyright 2020-2022 Safeheron Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.safeheron.com/opensource/license.html
 */
#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/hex.h"
#include "../src/crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

void print_hex(const uint8_t* buff, size_t size)
{
    if (!buff) return;

    for (size_t i = 0; i < size; i++) {
        printf("%02X", buff[i]);
    }
    printf("\n");
}

int test_curve_sign(CurveType type, BN &privkey, CurvePoint &pubkey, int times)
{
    int cur_time = 0;
    int sig_len = 64;
    const int DIGEST_SIZE = 32;
    uint8_t digest[DIGEST_SIZE] = {0};
    uint8_t sig[64] = {0};

    do {
        safeheron::rand::RandomBytes(digest, DIGEST_SIZE);
        printf("data: "); print_hex(digest, DIGEST_SIZE);

        memset(sig, 0, 64);
        safeheron::curve::ecdsa::Sign(type, privkey, digest, sig);
        printf("sign: "); print_hex(sig, 64);

        bool pass = safeheron::curve::ecdsa::Verify(type, pubkey, digest, sig);
        EXPECT_TRUE(pass == true);
        if (!pass) {
            printf("verify failed!\n");
        }
        else {
            printf("verify passed!\n");
        }

    }while (++cur_time < times);

    return 0;

}

TEST(curve_sign, SECP256K1)
{
    const Curve *curv = GetCurveParam(CurveType::SECP256K1);
    BN priv = safeheron::rand::RandomBNLtGcd(curv->n);
    CurvePoint pub = curv->g * priv;

    std::string priv_str;
    priv.ToHexStr(priv_str);
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    printf("Private Key: %s\n", priv_str.c_str());
    printf("Public Key: %s\n", pub.Inspect().c_str());
    test_curve_sign(CurveType::SECP256K1, priv, pub, 1000);
    printf("/*******************SECP256K1 Sign/Verify*********************/\n");
    printf("\n\n");
}

TEST(curve_sign, P256)
{
    const Curve *curv = GetCurveParam(CurveType::P256);
    BN priv = safeheron::rand::RandomBNLtGcd(curv->n);
    CurvePoint pub = curv->g * priv;

    std::string priv_str;
    priv.ToHexStr(priv_str);
    printf("/*******************P256 Sign/Verify*********************/\n");
    printf("Private Key: %s\n", priv_str.c_str());
    printf("Public Key: %s\n", pub.Inspect().c_str());
    test_curve_sign(CurveType::P256, priv, pub, 1000);
    printf("/*******************P256 Sign/Verify*********************/\n");
    printf("\n\n");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
