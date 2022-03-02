//
// Created by 何剑虹 on 2021/6/17.
//

#ifndef SAFEHERON_CURVE_H
#define SAFEHERON_CURVE_H

#include "crypto-bn/bn.h"
#include "curve_point.h"

namespace safeheron{
namespace curve {

class Curve {
public:
    const safeheron::bignum::BN p;
    const safeheron::bignum::BN a;
    const safeheron::bignum::BN b;
    const safeheron::bignum::BN c;
    const safeheron::bignum::BN d;
    const safeheron::bignum::BN n;
    const CurvePoint g;
    const ec_group_st* grp;

    Curve(const safeheron::bignum::BN _p,
          const safeheron::bignum::BN _a,
          const safeheron::bignum::BN _b,
          const safeheron::bignum::BN _c,
          const safeheron::bignum::BN _d,
          const safeheron::bignum::BN _n,
          const CurvePoint _g);
    ~Curve();
};


/**
 * 0, invalid
 *
 * 1 ~ 2^5-1, short curve
 * - SECP256K1 = 1,
 * - P256 = 2,
 *
 * 2^5 ~ 2^6-1, edwards curve
 * - ED25519 = 32,
 *
 * 2^6 ~ 2^6+2^5-1, montgomery curve
 * @param c_type
 * @return
 */
const ec_group_st *GetCurveGroup(CurveType c_type);
const Curve *GetCurveParam(CurveType c_type);

}
}

#endif //SAFEHERON_CURVE_H
