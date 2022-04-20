//
// Created by 何剑虹 on 2021/5/16.
//

#ifndef SAFEHERON_CURVE_POINT_H
#define SAFEHERON_CURVE_POINT_H

#include "crypto-bn/bn.h"
#include "curve_point.pb.h"
#include "mcl_wrapper.h"

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
    BLSG1  = 64,     //2
    BLSG2  = 96,     //3
};


inline void CurveInit()
{
	mcl_Init();
}

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
    union {
        BLS_G1 bls_g1_;
        BLS_G2 bls_g2_;
    };

public:
    /********************  constructor, destructor, assignment  ***********************/
    /**
     * An blank CurvePoint will be created, that means:
     *      CurvePoint point;
     *      assert(!point.IsValid());
     * It shouldn't be used for arithmetical operations.
     */
    explicit CurvePoint();

    /**
     * An CurvePoint on Curve of "c_type" will be created, which will be initiated as an infinity point.
     *
     *      CurvePoint point(CurveType::SECP256K1);
     *      assert(point.IsValid());
     *      assert(point.IsInfinity());
     *
     * @param c_type type of the curve
     */
    explicit CurvePoint(CurveType c_type);

    /**
     * Copy constructor.
     * @param point
     */
    CurvePoint(const CurvePoint &point);            // copy constructor

    /**
     * The constructor should be used carefully, usually invoked after the function "CurvePoint::ValidatePoint".
     *
     * For example:
     *
     *      if(!CurvePoint::ValidatePoint(x, y, cType)) return false;
     *      CurvePoint point(x, y, cType);
     *
     * @param x coordinate x of the curve point
     * @param y coordinate y of the curve point
     * @param c_type type of the curve
     */
    explicit CurvePoint(const safeheron::bignum::BN &x, const safeheron::bignum::BN &y, CurveType c_type);


    /**
     * Copy assignment.
     * @param point
     * @return
     */
    CurvePoint &operator=(const CurvePoint &point); // copy assignment
    //CurvePoint(CurvePoint &&num) noexcept;           // move constructor
    //CurvePoint &operator=(CurvePoint &&point) noexcept;// move assignment

    // Destructor.
    ~CurvePoint();

    // Return the type of the curve.
    CurveType GetCurveType() const;

    // Return the handler of the group.
    const ec_group_st* GetEcdsaCurveGrp() const;

    /**
     * Get information of the point
     * - < Infinity >
     * - < Curve: secp256k1, x: xxxxxxxxxx, y: xxxxxxxxxxxxxx >
     * @return
     */
    std::string Inspect() const;

    void RandomInit(const void *buf, size_t bufSize);

    /********************** encode, decode and validate  ******************************/
    // Check if the curve point is valid
    bool IsValid() const;

    /**
     * Check if the point with specified x and y is valid
     * @param x
     * @param y
     * @param c_type
     * @return true if it's a valid curve point, false otherwise.
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

    /**
     * Encode the point into 33 bytes(compressed format).
     * @param pub33
     */
    void EncodeCompressed(uint8_t* pub33) const;

    /**
     * Decode the point from 33 bytes(compressed format).
     * @param pub33
     */
    bool DecodeCompressed(const uint8_t* pub33, CurveType c_type);

    /**
     * Encode the point into 65 bytes(full public key).
     * @param pub33
     */
    void EncodeFull(uint8_t* pub65) const;

    /**
     * Decode the point from 65 bytes(full public key).
     * @param pub33
     */
    bool DecodeFull(const uint8_t* pub65, CurveType c_type);

    /**
     * Encode the edwards point into 32 bytes.
     * @param pub33
     */
    void EncodeEdwardsPoint(uint8_t *pub32) const;

    /**
     * Decode the edwards point from 32 bytes.
     * @param pub33
     */
    bool DecodeEdwardsPoint(uint8_t *pub32, CurveType c_type);

    /***************************  addition, multiplication...  ****************************/
    /**
     * Addition on curve: Res = P1 + P2
     * @param point
     * @return Res = *this + point
     */
    CurvePoint operator+(const CurvePoint &point) const;

    /**
     * Subtraction on curve: Res = P1 - P2
     * @param point
     * @return Res = *this - point
     */
    CurvePoint operator-(const CurvePoint &point) const;

    /**
     * Multiplication on curve: Res = P1 * n
     * @param point
     * @return Res = (*this) * bn
     */
    CurvePoint operator*(const safeheron::bignum::BN &bn) const;

    /**
     * Multiplication on curve: Res = P1 * n
     * @param point
     * @return Res = (*this) * n
     */
    CurvePoint operator*(long n) const;

    /**
     * Self-Addition on curve: P1 += P2
     * @param point
     * @return *this += point
     */
    CurvePoint &operator+=(const CurvePoint &point);

    /**
     * Self-Subtraction on curve: P1 -= P2
     * @param point
     * @return *this -= point
     */

    CurvePoint &operator-=(const CurvePoint &point);

    /**
     * Self-Multiplication on curve: P1 *= n
     * @param point
     * @return *this *= bn
     */
    CurvePoint &operator*=(const safeheron::bignum::BN &bn);

    /**
     * Self-Multiplication on curve: P1 *= n
     * @param point
     * @return *this *= bn
     */
    CurvePoint &operator*=(long n);

    /**
     * P1 = -P1
     * @return negative of the point.
     */
    CurvePoint neg() const;

    /**
     * Compare the two points: P1 == P2
     * @param point
     * @return  true if *this == point; false otherwise.
     */

    bool operator==(const CurvePoint &point) const;

    /**
     * Compare the two points: P1 != P2
     * @param point
     * @return  true if *this != point; false otherwise.
     */
    bool operator!=(const CurvePoint &point) const;


    /***************************  get coordinate x, y  **************************************/
    // Get coordinate x of the point
    safeheron::bignum::BN x() const;

    // Get coordinate x of the point
    safeheron::bignum::BN y() const;


    /***************************  serialization and deserialization ************************/
    /**
     * Serialize the point to proto object.
     * @param curvePoint
     * @return true if no check fails; false otherwise.
     */
    bool ToProtoObject(safeheron::proto::CurvePoint &curvePoint) const;

    /**
     * Deserialize the point from proto object.
     * @param curvePoint
     * @return true if no check fails; false otherwise.
     */
    bool FromProtoObject(const safeheron::proto::CurvePoint &curvePoint);

    /**
     * Serialize the point to base64 string.
     * @param curvePoint
     * @return true if no check fails; false otherwise.
     */
    bool ToBase64(std::string& base64) const;

    bool FromBase64(const std::string& base64);

    /**
     * Serialize the point to json.
     * @param curvePoint
     * @return true if no check fails; false otherwise.
     */
    bool ToJsonString(std::string &json_str) const;

    /**
     * Deserialize the point from json.
     * @param curvePoint
     * @return true if no check fails; false otherwise.
     */
    bool FromJsonString(const std::string &json_str);

private:
    /**
     * Reset the state of the point.
     * For example:
     *
     * CurvePoint p0();
     * assert(!p0.IsValid());
     *
     * CurvePoint p1(CurveType::SECP256K1);
     * assert(p1.IsValid());
     * assert(p1.IsInfinity());
     * p1.Reset();
     * assert(!p1.IsValid());
     * assert(p1 == p0);
     *
     */
    void Reset();

};

};
};
#endif //SAFEHERON_CURVE_POINT_H
