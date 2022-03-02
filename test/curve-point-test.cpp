//
// Created by 何剑虹 on 2020/10/22.
//
#include <cstring>
#include <google/protobuf/stubs/common.h>
#include "gtest/gtest.h"
#include "safeheron/crypto-bn/rand.h"
#include "safeheron/crypto-encode/hex.h"
#include "../src/crypto-curve/curve.h"

using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

void testCurveParameter(
        CurveType cType,
        BN p,
        BN a,
        BN b,
        BN c,
        BN d,
        BN n,
        BN gx,
        BN gy){
    const Curve* curv = safeheron::curve::GetCurveParam(cType);
    EXPECT_TRUE(curv->p == p);
    EXPECT_TRUE(curv->a == a);
    EXPECT_TRUE(curv->b == b);
    EXPECT_TRUE(curv->c == c);
    EXPECT_TRUE(curv->d == d);
    EXPECT_TRUE(curv->n == n);
    //std::string str;
    //curv->g.x().ToHexStr(str);
    //std::cout << "g.x: " << str << std::endl;
    //curv->g.y().ToHexStr(str);
    //std::cout << "g.y: " << str << std::endl;
    EXPECT_TRUE(curv->g.x() == gx);
    EXPECT_TRUE(curv->g.y() == gy);
}

TEST(CurvePoint, CurveParameter)
{
    testCurveParameter(CurveType::SECP256K1,
                       BN::FromHexStr("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
                       BN::FromHexStr("0000000000000000000000000000000000000000000000000000000000000000"),
                       BN::FromHexStr("0000000000000000000000000000000000000000000000000000000000000007"),
                       BN::FromHexStr("0"),
                       BN::FromHexStr("0"),
                       BN::FromHexStr("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
                       BN::FromHexStr("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                       BN::FromHexStr("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
                       );

    testCurveParameter(CurveType::P256,
                       BN::FromHexStr("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
                       BN::FromHexStr("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
                       BN::FromHexStr("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
                       BN::FromHexStr("0"),
                       BN::FromHexStr("0"),
                       BN::FromHexStr("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
                       BN::FromHexStr("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
                       BN::FromHexStr("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );

    testCurveParameter(CurveType::ED25519,
                       BN::FromHexStr("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
                       BN("-1", 10),
                       BN::FromHexStr("0"),
                       BN::FromHexStr("1"),
                       BN::FromHexStr("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
                       BN::FromHexStr("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
                       BN::FromHexStr("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"),
                       BN::FromHexStr("6666666666666666666666666666666666666666666666666666666666666658")
    );
}

void testUniverseEncode(const char *x_hex, const char *y_hex, const std::string &pub33_hex, const std::string &pub65_hex, CurveType cType){
    CurvePoint point;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(point.PointFromX(x, y.IsOdd(), cType));
    CurvePoint p1(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(point == p1);
    std::string str;
    //p1.x().ToHexStr(str);
    //std::cout << "p1.x: " << str << std::endl;
    //p1.y().ToHexStr(str);
    //std::cout << "p1.y: " << str << std::endl;
    //point.x().ToHexStr(str);
    //std::cout << "point.x: " << str << std::endl;
    //point.y().ToHexStr(str);
    //std::cout << "point.y: " << str << std::endl;

    // Decode compressed public key, of which the length is 33.
    CurvePoint p2;
    std::string b33 = safeheron::encode::hex::DecodeFromHex(pub33_hex);
    EXPECT_TRUE(p2.DecodeCompressed(reinterpret_cast<const uint8_t *>(b33.c_str()), cType));
    EXPECT_TRUE(p1 == p2);
    //p2.x().ToHexStr(str);
    //std::cout << "p2.x: " << str << std::endl;
    //p2.y().ToHexStr(str);
    //std::cout << "p2.y: " << str << std::endl;

    // Encode compressed public key, of which the length is 33.
    uint8_t out_b33[33];
    p2.EncodeCompressed(out_b33);
    std::string out_pub33_hex = safeheron::encode::hex::EncodeToHex(out_b33, 33);
    EXPECT_TRUE(strncasecmp(pub33_hex.c_str(), out_pub33_hex.c_str(), 66) == 0);
    //std::cout << pub33_hex << std::endl;
    //std::cout << out_pub33_hex << std::endl;

    // Decode full public key, of which the length is 65.
    CurvePoint p3;
    std::string b65 = safeheron::encode::hex::DecodeFromHex(pub65_hex);
    EXPECT_TRUE(p3.DecodeFull(reinterpret_cast<const uint8_t *>(b65.c_str()), cType));
    EXPECT_TRUE(p1 == p3);

    // Encode full public key, of which the length is 65.
    uint8_t out_b65[65];
    p3.EncodeFull(out_b65);
    std::string out_pub65_hex = safeheron::encode::hex::EncodeToHex(out_b65, 65);
    EXPECT_TRUE(strncasecmp(pub65_hex.c_str(), out_pub65_hex.c_str(), 130) == 0);
    //std::cout << pub65_hex << std::endl;
    //std::cout << out_pub65_hex << std::endl;
}

TEST(CurvePoint, UniverseEncode)
{
    testUniverseEncode("a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                 "893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
                 "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
                 "04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
                 CurveType::SECP256K1);
    testUniverseEncode("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f",
                 "878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773",
                 "03cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f",
                 "04cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773",
                 CurveType::P256);
    testUniverseEncode("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                 "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                 "02602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                 "04602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                 CurveType::ED25519);
}


void testEdwardsEncode(const char *x_hex, const char *y_hex, const std::string &pub32_hex, CurveType cType){
    CurvePoint point;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(point.PointFromX(x, y.IsOdd(), cType));
    CurvePoint p1(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(point == p1);
    std::string str;
    //p1.x().ToHexStr(str);
    //std::cout << "p1.x: " << str << std::endl;
    //p1.y().ToHexStr(str);
    //std::cout << "p1.y: " << str << std::endl;
    //point.x().ToHexStr(str);
    //std::cout << "point.x: " << str << std::endl;
    //point.y().ToHexStr(str);
    //std::cout << "point.y: " << str << std::endl;

    // Decode compressed public key, of which the length is 33.
    CurvePoint p2;
    std::string b32 = safeheron::encode::hex::DecodeFromHex(pub32_hex);
    EXPECT_TRUE(p2.DecodeEdwardsPoint((uint8_t *) b32.c_str(), cType));
    EXPECT_TRUE(p1 == p2);
    //p2.x().ToHexStr(str);
    //std::cout << "p2.x: " << str << std::endl;
    //p2.y().ToHexStr(str);
    //std::cout << "p2.y: " << str << std::endl;

    // Encode compressed public key, of which the length is 33.
    uint8_t out_b32[32];
    p2.EncodeEdwardsPoint(out_b32);
    std::string out_pub32_hex = safeheron::encode::hex::EncodeToHex(out_b32, 32);
    EXPECT_TRUE(strncasecmp(pub32_hex.c_str(), out_pub32_hex.c_str(), 66) == 0);
    //std::cout << pub32_hex << std::endl;
    //std::cout << out_pub32_hex << std::endl;

}

TEST(CurvePoint, EncodeEdwards)
{
    testEdwardsEncode("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
                       "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
                       "2c7be86ab07488ba43e8e03d85a67625cfbf98c8544de4c877241b7aaafc7fe3",
                       CurveType::ED25519);
    testEdwardsEncode("4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47",
                       "405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5",
                       "c581fda28ec7694c252b376c755ba228899a7608318b3160a9bd14d4cda05ec0",
                       CurveType::ED25519);
    testEdwardsEncode("7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                       "ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
                       "e7caaa83373a94afae43fec59b447c99ba282b19a7616c24c785ad8966a1e10e",
                       CurveType::ED25519);
}

TEST(CurvePoint, Ed25519_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f", 16),
                      BN("637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c", 16),
                      CurveType::ED25519);
    // p0 = g^100
    CurvePoint p1(BN("4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47", 16),
                      BN("405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5", 16),
                      CurveType::ED25519);
    // p0 = g^1000
    CurvePoint p2(BN("7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e", 16),
                      BN("ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7", 16),
                      CurveType::ED25519);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::ED25519);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::ED25519);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);
    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::ED25519);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::ED25519);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);
}

TEST(CurvePoint, Secp256k1_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7", 16),
                         BN("893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7", 16),
                         CurveType::SECP256K1);
    // p0 = g^100
    CurvePoint p1(BN("ed3bace23c5e17652e174c835fb72bf53ee306b3406a26890221b4cef7500f88", 16),
                         BN("e57a6f571288ccffdcda5e8a7a1f87bf97bd17be084895d0fce17ad5e335286e", 16),
                         CurveType::SECP256K1);
    // p0 = g^1000
    CurvePoint p2(BN("4a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad", 16),
                         BN("baf1e702eb2a8badae14ba09a26a8ca7cb1127b64b2c39a1c7ba61f4a3c62601", 16),
                         CurveType::SECP256K1);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::SECP256K1);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::SECP256K1);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);
    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::SECP256K1);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::SECP256K1);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);
}

TEST(CurvePoint, P256_Add_Mul)
{
    // p0 = g^10
    CurvePoint p0(BN("cef66d6b2a3a993e591214d1ea223fb545ca6c471c48306e4c36069404c5723f", 16),
                         BN("878662a229aaae906e123cdd9d3b4c10590ded29fe751eeeca34bbaa44af0773", 16),
                         CurveType::P256);
    // p1 = g^100
    CurvePoint p1(BN("490a19531f168d5c3a5ae6100839bb2d1d920d78e6aeac3f7da81966c0f72170", 16),
                         BN("bbcd2f21db581bd5150313a57cfa2d9debe20d9f460117b588fcf9b0f4377794", 16),
                         CurveType::P256);
    // p2 = g^1000
    CurvePoint p2(BN("b8fa1a4acbd900b788ff1f8524ccfff1dd2a3d6c917e4009af604fbd406db702", 16),
                         BN("9a5cc32d14fc837266844527481f7f06cb4fb34733b24ca92e861f72cc7cae37", 16),
                         CurveType::P256);
    EXPECT_TRUE(p0 * 10 == p1);
    EXPECT_TRUE(p1 * 10 == p2);
    CurvePoint p3(CurveType::P256);
    p3 = p0;
    for(int i = 0; i < 9; i++){
        p3 += p0;
    }
    EXPECT_TRUE(p3 == p1);
    CurvePoint p4(CurveType::P256);
    p4 += p1;
    for(int i = 0; i < 9; i++){
        p4 += p1;
    }
    EXPECT_TRUE(p4 == p2);

    // P5 - P1 * 9 = P1
    CurvePoint p5(CurveType::P256);
    p5 = p2;
    for(int i = 0; i < 9; i++){
        p5 -= p1;
    }
    EXPECT_TRUE(p5 == p1);
    // P6 - P0 * 99 = P0
    CurvePoint p6(CurveType::P256);
    p6 = p2;
    for(int i = 0; i < 99; i++){
        p6 -= p0;
    }
    EXPECT_TRUE(p6 == p0);


    CurvePoint p7;
    EXPECT_TRUE(p7.PointFromXY(p1.x(), p1.y(), p1.GetCurveType()));
    EXPECT_TRUE(p7.PointFromXY(p2.x(), p2.y(), p2.GetCurveType()));
    EXPECT_TRUE(p7.PointFromXY(p3.x(), p3.y(), p3.GetCurveType()));
}

void test_Edwards_PointFromY(const char *x_hex, const char *y_hex, CurveType cType){
    CurvePoint p1, p2;
    BN x(x_hex, 16);
    BN y(y_hex, 16);
    EXPECT_TRUE(CurvePoint::ValidatePoint(x, y, cType));
    EXPECT_TRUE(p1.PointFromX(x, y.IsOdd(), cType));
    EXPECT_TRUE(p2.PointFromY(y, x.IsOdd(), cType));
    CurvePoint p0(x, y, cType); // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    EXPECT_TRUE(p0 == p1);
    EXPECT_TRUE(p0 == p2);

    CurvePoint p3;
    EXPECT_TRUE(p3.PointFromXY(x, y, cType));
}

TEST(CurvePoint, MakeCurvePoint)
{
    test_Edwards_PointFromY(
            "602c797e30ca6d754470b60ed2bc8677207e8e4ed836f81444951f224877f94f",
            "637ffcaa7a1b2477c8e44d54c898bfcf2576a6853de0e843ba8874b06ae87b2c",
            CurveType::ED25519);
    test_Edwards_PointFromY(
            "4b87a1147457b111116b878cfc2312de451370ac38fe8690876ef6ac346fd47",
            "405ea0cdd414bda960318b3108769a8928a25b756c372b254c69c78ea2fd81c5",
            CurveType::ED25519);
    test_Edwards_PointFromY(
            "7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
            "ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
            CurveType::ED25519);
}

void testNeg(CurveType cType){
    CurvePoint zero(cType); // Initialize as zero
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    CurvePoint a = curv->g * 10;
    CurvePoint b = curv->g * 100;
    CurvePoint a_neg = a.neg();
    CurvePoint b_neg = b.neg();
    EXPECT_TRUE( a + a_neg == zero);
    EXPECT_TRUE( b + b_neg == zero);
}

TEST(CurvePoint, Neg)
{
    testNeg(CurveType::SECP256K1);
    testNeg(CurveType::P256);
    testNeg(CurveType::ED25519);
}

void testSerialize(CurveType cType){
    const Curve *curv = safeheron::curve::GetCurveParam(cType);
    // base64 encode
    CurvePoint a = curv->g * 10;
    CurvePoint b(cType);
    std::string base64;
    EXPECT_TRUE(a.ToBase64(base64));
    EXPECT_TRUE(b.FromBase64(base64));
    EXPECT_TRUE(a == b);

    std::string str;
    a.x().ToHexStr(str);
    //std::cout << "a.x = " << str << std::endl;
    a.y().ToHexStr(str);
    //std::cout << "a.y = " << str << std::endl;
    b.x().ToHexStr(str);
    //std::cout << "b.x = " << str << std::endl;
    b.y().ToHexStr(str);
    //std::cout << "b.y = " << str << std::endl;

    // json string
    std::string jsonStr;
    EXPECT_TRUE(a.ToJsonString(jsonStr));
    EXPECT_TRUE(b.FromJsonString(jsonStr));
    EXPECT_TRUE(a == b);
}

TEST(CurvePoint, Serialize)
{
    testSerialize(CurveType::SECP256K1);
    testSerialize(CurveType::P256);
    testSerialize(CurveType::ED25519);
}


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
