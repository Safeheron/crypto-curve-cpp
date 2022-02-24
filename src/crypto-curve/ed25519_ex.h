//
// Created by Sword03 on 2022/2/24.
//

#ifndef CRYPTO_CURVE_CPP_ED25519_EX_H
#define CRYPTO_CURVE_CPP_ED25519_EX_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "ed25519-donna/ed25519.h"

/*
 * pk = G * sk
 */
void ed25519_publickey_pure(const ed25519_secret_key sk, ed25519_public_key pk);

/*
 * res = -pk
 */
int ed25519_publickey_neg(ed25519_public_key res, ed25519_public_key pk);


/*
 * res = pk * sk
 */
int ed25519_scalarmult_pure(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);

/*
 * res = pk1 * pk2
 */
int ed25519_cosi_combine_two_publickeys(ed25519_public_key res, CONST ed25519_public_key pk1, CONST ed25519_public_key pk2);

#if defined(__cplusplus)
}
#endif

#endif //CRYPTO_CURVE_CPP_ED25519_EX_H
