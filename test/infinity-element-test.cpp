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
#include "safeheron/crypto-bn/rand.h"
#include "safeheron/crypto-encode/hex.h"
#include "../src/crypto-curve/curve.h"
#include "../src/crypto-curve/eddsa.h"


using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

void testInifnity(CurveType type)
{
    CurvePoint a(type);
    EXPECT_TRUE(a.x() == 0);
    EXPECT_TRUE(a.y() == 0);
    EXPECT_TRUE(a.IsInfinity());
}

TEST(CurvePoint, Infinity)
{
    testInifnity(CurveType::SECP256K1);
    testInifnity(CurveType::P256);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
