//
// Created by 何剑虹 on 2021/5/18.
//

#ifndef CPP_MPC_CURVE_ECDSA_H
#define CPP_MPC_CURVE_ECDSA_H

#include "curve.h"
#include "crypto-bn/bn.h"


namespace safeheron{
namespace curve {
namespace ecdsa {

void Sign(safeheron::curve::CurveType c_type, const safeheron::bignum::BN &priv,
          const uint8_t *digest, uint8_t *sig64, uint8_t *pv,
          int (*is_canonical)(uint8_t v, uint8_t sig[64]));
bool Verify(CurveType cType, const CurvePoint &pub,
            const uint8_t *sig64, const uint8_t *digest);

bool SigToDer(const uint8_t *sig, uint8_t *der);
bool SigFromDer(const uint8_t *der, size_t der_len, uint8_t sig[64]);

bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const safeheron::bignum::BN &m,
                      const safeheron::bignum::BN &r,
                      const safeheron::bignum::BN &s,
                      uint j);

bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const uint8_t *sig64, uint sig_len,
                      const uint8_t *digest, uint digest_len,
                      int v);

bool VerifyPublicKey(const safeheron::curve::CurvePoint &expected_pub,
                     safeheron::curve::CurveType c_type,
                     const safeheron::bignum::BN &m,
                     const safeheron::bignum::BN &r,
                     const safeheron::bignum::BN &s,
                     uint v);

bool VerifyPublicKey(const safeheron::curve::CurvePoint &pub,
                     safeheron::curve::CurveType c_type,
                     const uint8_t *sig64, uint sig_len,
                     const uint8_t *digest, uint digest_len,
                     uint v);

};
};
};


#endif //CPP_MPC_CURVE_ECDSA_H
