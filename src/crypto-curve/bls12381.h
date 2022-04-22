/**
 * BLS 12 381
 */

#ifndef CPP_MPC_CURVE_BLS12381_H
#define CPP_MPC_CURVE_BLS12381_H

#include "curve.h"
#include "crypto-bn/bn.h"

namespace safeheron{
namespace curve {
namespace bls12_381 {

bool blsGetPublicKey(const CurveType pub_type,CurvePoint &pub, const safeheron::bignum::BN &priv);
bool blsSign(const CurveType sig_type,CurvePoint &sig, const safeheron::bignum::BN &priv, const void *msg, size_t len);
bool blsVerify(const CurveType pub_type,const CurveType sig_type,const CurvePoint &sig, const CurvePoint &pub, const void *msg, size_t len);

};
};
};

#endif //CPP_MPC_CURVE_EDDSA_H
