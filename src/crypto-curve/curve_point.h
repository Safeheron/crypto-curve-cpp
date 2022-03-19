//
// Created by 何剑虹 on 2021/5/16.
//

#ifndef SAFEHERON_CURVE_POINT_H
#define SAFEHERON_CURVE_POINT_H

#include "crypto-bn/bn.h"
#include "curve_point.pb.h"

struct ec_group_st;
struct ec_point_st;

typedef unsigned char ed25519_public_key_byte32[32];

namespace safeheron{
namespace curve{

/**
 * Curve type
 */
enum class CurveType: uint32_t {
    // 0, invalid
    INVALID_CURVE = 0xFFFFFFFF,
    // 1 ~ 2^5-1, short curve
    SECP256K1 = 1,
    P256 = 2,
    // 2^5 ~ 2^6-1, edwards curve
    ED25519 = 32,
    // 2^6 ~ 2^6+2^5-1, montgomery curve
};

//class 
/**
 * Curve Point
 */
class CurvePoint {
    CurveType curve_type_;
    const ec_group_st* curve_grp_;
    union {
        ec_point_st* short_point_;
        ed25519_public_key_byte32 edwards_point_;
    };

public:
    /********************  constructor, destructor, assignment  ***********************/
    explicit CurvePoint(); // You will get an invalid CurvePoint.( obj.IsValid() == false )
    explicit CurvePoint(CurveType c_type);
    CurvePoint(const CurvePoint &point);            // copy constructor
    // Be careful! "CurvePoint::ValidatePoint" should be invoked firstly.
    // not suggested, not safe
    explicit CurvePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);
    CurvePoint &operator=(const CurvePoint &point); // copy assignment
    //CurvePoint(CurvePoint &&num) noexcept;           // move constructor, unnecessary
    //CurvePoint &operator=(CurvePoint &&point) noexcept;// move assignment, unnecessary
    ~CurvePoint();

    CurveType GetCurveType() const;
    const ec_group_st* GetEcdsaCurveGrp() const;

    /**
     * Get information of the point
     * - < Infinity >
     * - < Curve: secp256k1, x: xxxxxxxxxx, y: xxxxxxxxxxxxxx >
     * @return
     */
    std::string Inspect() const;

    /********************** encode, decode and validate  ******************************/
    // If the curve point is valid
    bool IsValid() const;

    /**
     * If the point with specified x and y is valid
     * @param x
     * @param y
     * @param c_type
     * @return
     */
    static bool ValidatePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);
    bool PointFromXY(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);

    /**
     * P1 is infinity
     * @return
     */
    bool IsInfinity() const;

    /**
     * Recover point from coordinate x
     * @param x
     * @param yIsOdd
     * @param c_type
     * @return
     */
    bool PointFromX(safeheron::bignum::BN &x, bool yIsOdd, CurveType c_type);

    /**
     * Recover point from coordinate y, only for edwards point
     * @param y
     * @param xIsOdd
     * @param c_type
     * @return
     */
    bool PointFromY(safeheron::bignum::BN &y, bool xIsOdd, CurveType c_type);

    // Compressed public key (33 bytes)
    void EncodeCompressed(uint8_t* pub33) const;
    bool DecodeCompressed(const uint8_t* pub33, CurveType c_type);

    // Full public key (65 bytes)
    void EncodeFull(uint8_t* pub65) const;
    bool DecodeFull(const uint8_t* pub65, CurveType c_type);

    // Only for edwards point
    void EncodeEdwardsPoint(uint8_t *pub32) const;
    bool DecodeEdwardsPoint(uint8_t *pub32, CurveType c_type);

    /***************************  addition, multiplication...  ****************************/
    // Res = P1 + P2
    CurvePoint operator+(const CurvePoint &point) const;
    // Res = P1 - P2
    CurvePoint operator-(const CurvePoint &point) const;
    // Res = P1 * n
    CurvePoint operator*(const safeheron::bignum::BN &bn) const;
    // Res = P1 * n
    CurvePoint operator*(long n) const;

    // P1 += P2
    CurvePoint &operator+=(const CurvePoint &point);
    // P1 -= P2
    CurvePoint &operator-=(const CurvePoint &point);
    // P1 *= n
    CurvePoint &operator*=(const safeheron::bignum::BN &bn);
    // P1 *= n
    CurvePoint &operator*=(long n);

    // P1 = -P1
    CurvePoint neg() const;

    // P1 == P2
    bool operator==(const CurvePoint &point) const;
    // P1 != P2
    bool operator!=(const CurvePoint &point) const;


    /***************************  get coordinate x, y  **************************************/
    // Get coordinate x, y
    safeheron::bignum::BN x() const;
    safeheron::bignum::BN y() const;


    /***************************  serialization and deserialization ************************/
    bool ToProtoObject(safeheron::proto::CurvePoint &curvePoint) const;
    bool FromProtoObject(const safeheron::proto::CurvePoint &curvePoint);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);

private:
    void Reset();

};

};
};
#endif //SAFEHERON_CURVE_POINT_H
