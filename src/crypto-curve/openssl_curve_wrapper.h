#ifndef _SAFEHERON_OPENSSL_CURVE_WRAPPER_H_
#define _SAFEHERON_OPENSSL_CURVE_WRAPPER_H_

#include "crypto-bn/bn.h"

struct ec_group_st;
struct ec_point_st;

namespace safeheron{
namespace _openssl_curve_wrapper
{
    bool point_set_infinity(const ec_group_st* grp, ec_point_st *p);
    bool point_is_infinity(const ec_group_st* grp, const ec_point_st *p);
    int read_pubkey(const ec_group_st* grp, const uint8_t *pub_key, ec_point_st *pub);
    int write_pubkey(const ec_group_st* grp, const ec_point_st *pub, uint8_t *pub_key, bool compress);
    int point_add(const ec_group_st* grp, const ec_point_st *cp1, ec_point_st *cp2);
    int point_multiply(const ec_group_st* grp, const bignum_st *k, const ec_point_st *p, ec_point_st *res);
    int point_neg(const ec_group_st* grp, const ec_point_st *p, ec_point_st *res);
    int sign_digest(const ec_group_st* grp, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig);
    int verify_digest(const ec_group_st* grp, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);
    //
    bool validate_pubkey(const ec_group_st* grp, const ec_point_st *pub);
    int uncompress_coords(const ec_group_st* grp, uint8_t odd, const bignum_st *x, bignum_st *y);
};
};

#endif //_SAFEHERON_OPENSSL_CURVE_WRAPPER_H_