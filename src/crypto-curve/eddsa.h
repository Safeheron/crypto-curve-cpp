/**
 * IETF 8709
 * Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol
 */

#ifndef CPP_MPC_CURVE_EDDSA_H
#define CPP_MPC_CURVE_EDDSA_H

#include "curve.h"
#include "crypto-bn/bn.h"

namespace safeheron{
namespace curve {
namespace eddsa {

std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const CurvePoint &pub,
                 const uint8_t *msg, size_t len);

bool Verify(const CurveType c_type,
            const CurvePoint &pub,
            const uint8_t *sig,
            const uint8_t *msg, size_t len);

};
};
};

#endif //CPP_MPC_CURVE_EDDSA_H
