#include "openssl_curve_wrapper.h"
#include "curve_point.h"
#include <assert.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

namespace safeheron{
namespace _openssl_curve_wrapper {

bool point_set_infinity(const ec_group_st* grp, ec_point_st *p)
{
    return (1 == EC_POINT_set_to_infinity(grp, p));
}

bool point_is_infinity(const ec_group_st* grp, const ec_point_st *p)
{
    return (1 == EC_POINT_is_at_infinity(grp, p));
}

int read_pubkey(const ec_group_st* grp, const uint8_t *pub_key, ec_point_st *pub)
{
    int ret = 0;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    assert(pub_key);
    assert(pub);

    if (!(bn_x = BN_new()) ||
        !(bn_y = BN_new())) {
        //fprintf(stderr, "BN_new() return null!\n");
        ret = -1;
        goto err;
    }

    if (pub_key[0] == 0x04) {
        if (!BN_bin2bn(pub_key + 1, 32, bn_x)) {
            //fprintf(stderr, "BN_bin2bn() return null!\n");
            ret = -1;
            goto err;
        }
        if (!BN_bin2bn(pub_key + 33, 32, bn_y)) {
            //fprintf(stderr, "BN_bin2bn() return null!\n");
            ret = -1;
            goto err;
        }
    }

    if (pub_key[0] == 0x02 || pub_key[0] == 0x03) {  // compute missing y coords
        if (!BN_bin2bn(pub_key + 1, 32, bn_x)) {
            //fprintf(stderr, "BN_bin2bn() return null!\n");
            ret = -1;
            goto err;
        }
        uncompress_coords(grp, pub_key[0], bn_x, bn_y);
    }

    if ((ret = EC_POINT_set_affine_coordinates(grp, pub, bn_x, bn_y, nullptr)) != 1) {
        //fprintf(stderr, "EC_POINT_set_affine_coordinates() failed! ret : %d\n", ret);
        goto err;
    }
    if ((ret = validate_pubkey(grp, pub)) != 1) {
        //fprintf(stderr, "validate_pubkey() failed! ret : %d\n", ret);
        goto err;
    }

    ret = 0; // 0 is OK

err:
    if (bn_x) {
        BN_clear_free(bn_x);
        bn_x = nullptr;
    }
    if (bn_y) {
        BN_clear_free(bn_y);
        bn_y = nullptr;
    }
    return ret;
}

int write_pubkey(const ec_group_st* grp, const ec_point_st *pub, uint8_t *pub_key, bool compress)
{
    int ret = 0;
    bool at_infinity = false;
    uint8_t tmp[64] = {0};
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;

    assert(pub);
    assert(pub_key);

    if (!(bn_x = BN_new()) ||
        !(bn_y = BN_new())) {
        //fprintf(stderr, "BN_new() return null!\n");
        goto err;
    }

    if (EC_POINT_is_at_infinity(grp, pub) == 1) {
        at_infinity = true;
    }

    if (!at_infinity) {
        if ((ret = EC_POINT_get_affine_coordinates(grp, pub, bn_x, bn_y, nullptr)) != 1) {
            //fprintf(stderr, "EC_POINT_get_affine_coordinates() failed! ret: %d\n", ret);
            ret = -1;
            goto err;
        }
    }
    else {
        BN_zero(bn_x);
        BN_zero(bn_y);
    }

    if (compress) {
        memset(pub_key, 0, 33);
        if (BN_is_odd(bn_y)) {
            pub_key[0] = 0x03;
        }
        else {
            pub_key[0] = 0x02;
        }
        if (!at_infinity) {
            if ((ret = BN_bn2bin(bn_x, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + 33 - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 1, src, 32);
            }
        }
        ret = 0;
    }
    else {
        memset(pub_key, 0, 65);
        pub_key[0] = 0x04;
        //
        if (!at_infinity) {
            if ((ret = BN_bn2bin(bn_x, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + 33 - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 1, src, 32);
            }
            //
            if ((ret = BN_bn2bin(bn_y, tmp)) == 0) {
                ret = -1;
                goto err;
            }
            if (ret < 32) {
                uint8_t *des = pub_key + (33+32) - ret;
                memcpy(des, tmp, ret);
            } else {
                uint8_t *src = tmp + ret - 32;
                memcpy(pub_key + 33, src, 32);
            }
        }

        ret = 0; // 0 is OK
    }

err:
    if (bn_x) {
        BN_clear_free(bn_x);
        bn_x = nullptr;
    }
    if (bn_y) {
        BN_clear_free(bn_y);
        bn_y = nullptr;
    }

    return ret;    
}

// cp2 = cp1 + cp2
int point_add(const ec_group_st* grp, const ec_point_st *cp1, ec_point_st *cp2)
{
    int ret = 0;

    if ((ret = EC_POINT_add(grp, cp2, cp1, cp2, nullptr)) != 1) {
        //fprintf(stderr, "EC_POINT_add() failed! ret: %d\n", ret);
        return ret;
    }
    return  0;  // 0 is OK!
}

// res = k * p
int point_multiply(const ec_group_st* grp, const bignum_st *k, const ec_point_st *p, ec_point_st *res)
{
    int ret = 0;
    if ((ret = EC_POINT_mul(grp, res, nullptr, p, k, nullptr)) != 1) {
        //fprintf(stderr, "EC_POINT_mul() failed! ret: %d\n", ret);
        return ret;
    }
    return  0;  // 0 is OK!
}

// p = (x, y)
// res = (x, -y)
int point_neg(const ec_group_st* grp, const ec_point_st *p, ec_point_st *res)
{
    int ret = 0;

    if ((ret = EC_POINT_copy(res, p)) != 1) {
        //fprintf(stderr, "EC_POINT_copy() failed! ret: %d\n", ret);
        return ret;
    }
    
    if ((ret = EC_POINT_invert(grp, res, nullptr)) != 1) {
        //fprintf(stderr, "EC_POINT_invert() failed! ret: %d\n", ret);
        return ret;
    }
    return  0;  // 0 is OK!
}

// priv_key is a 32 byte big endian stored number
// sig is 64 bytes long array for the signature
// digest is 32 bytes of digest
int sign_digest(const ec_group_st* grp, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig)
{
    int ret = 0;
    BIGNUM* priv = nullptr;
    const BIGNUM* sig_r = nullptr;
    const BIGNUM* sig_s = nullptr;
    EC_KEY* ec_key = nullptr;
    ECDSA_SIG* ecdsa_sig = nullptr;
    const int MAX_TRY_TIMES = 10000;

    assert(grp);
    assert(priv_key && digest && sig);

    if (!(priv = BN_new()) ||
        !(ec_key = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(grp)))) {
        ret = 1;
        goto err;
    }

    if (!BN_bin2bn(priv_key, 32, priv) ||
        (ret = EC_KEY_set_private_key(ec_key, priv)) != 1) {
        ret = 1;
        goto err;
    }

    if (!(ecdsa_sig = ECDSA_do_sign(digest, 32, ec_key))) {
        ret = 2;
        goto err;
    }

    if (!(sig_r = ECDSA_SIG_get0_r(ecdsa_sig)) ||
        !(sig_s = ECDSA_SIG_get0_s(ecdsa_sig))) {
        ret = 2;
        goto err;
    }

    if ((ret = BN_bn2bin(sig_r, sig)) <= 0 ||
        (ret = BN_bn2bin(sig_s, sig + 32))) {
        ret = 2;
        goto err;
    }

    ret = 0;
    
err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
    if (priv) {
        BN_clear_free(priv);
        priv = nullptr;
    }
    return ret;
}

// pub_key is a 65 byte big endian stored number
// sig is 64 bytes long array for the signature
// digest is 32 bytes of digest
// returns 0 if verification succeeded
int verify_digest(const ec_group_st* grp, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest)
{
    int ret = 0;
    EC_POINT* pub = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;
    BIGNUM* bn_r = nullptr;
    BIGNUM* bn_s = nullptr;
    BN_CTX* ctx = nullptr;
    EC_KEY* ec_key = nullptr;
    ECDSA_SIG* ecdsa_sig = nullptr;

    assert(grp);
    assert(pub_key && sig && digest );

    // only support uncompress public key
    if (pub_key[0] != 0x04) {
        return 1;
    }

    if (!(pub = EC_POINT_new(grp))) {
        ret = 1;
        goto err;
    }

    if (!(ctx = BN_CTX_new())) {
        ret = 1;
        goto err;
    }
    BN_CTX_start(ctx);
    if (!(bn_x = BN_CTX_get(ctx)) ||
        !(bn_y = BN_CTX_get(ctx)) ||
        !(bn_r = BN_CTX_get(ctx)) ||
        !(bn_s = BN_CTX_get(ctx))) {
        ret = 1;
        goto err;
    }
    
    if (!BN_bin2bn(pub_key+1, 32, bn_x) ||
        !BN_bin2bn(pub_key+33, 32, bn_y) ||
        (ret = EC_POINT_set_affine_coordinates(grp, pub, bn_x, bn_y, ctx)) != 1) {
        ret = 1;
        goto err;
    }
    if ((ret = EC_KEY_set_public_key(ec_key, pub)) != 1) {
        ret = 1;
        goto err;
    }

    if (!BN_bin2bn(sig, 32, bn_r) ||
        !BN_bin2bn(sig + 32, 32, bn_s) ||
        !(ecdsa_sig = ECDSA_SIG_new()) ||
        (ret = ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s)) != 1) {
        ret = 1;
        goto err;
    }

    if ((ret = ECDSA_do_verify(digest, 32, ecdsa_sig, ec_key)) != 1) {
        ret = 1;
        goto err;
    }

    ret = 0;    //OK
    
err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        ctx = nullptr;
    }
    if (ec_key) {
        EC_KEY_free(ec_key);
        ec_key = nullptr;
    }
    if (pub) {
        EC_POINT_free(pub);
        pub = nullptr;
    }

    return ret;
}

// Verifies that:
//   - pub is not the point at infinity.
//   - pub->x and pub->y are in range [0,p-1].
//   - pub is on the curve.
// We assume that all curves using this code have cofactor 1, so there is no
// need to verify that pub is a scalar multiple of G.
// ok return 1, otherwise return 0
bool validate_pubkey(const ec_group_st* grp, const ec_point_st *pub)
{
    if (EC_POINT_is_at_infinity(grp, pub) == 1) {
        return false;
    }

    if (EC_POINT_is_on_curve(grp, pub, nullptr) != 1) {
        return false;
    }

    return true;
}

int uncompress_coords(const ec_group_st* grp, uint8_t odd, const bignum_st *x, bignum_st *y)
{
    int ret = 0;
    BIGNUM* bn_y = nullptr;
    BN_CTX* ctx = nullptr;
    EC_POINT* p = nullptr;

    assert(grp);
    assert(x);
    assert(y);

    if (!(ctx = BN_CTX_new()) ||
        !(bn_y = BN_new())) {
        ret = -1;
        goto err;
    }

    if (!(p = EC_POINT_new(grp)) ||
        (ret = EC_POINT_set_compressed_coordinates(grp, p, x, 32, ctx)) != 1 ||
        (ret = EC_POINT_get_affine_coordinates(grp, p, nullptr, bn_y, ctx)) != 1) {
        ret = 1;
        goto err;
    }
    BN_copy(y, bn_y);

    ret = 0;    // 0 is OK!

err:
    if (bn_y) {
        BN_clear_free(bn_y);
        bn_y = nullptr;
    }
    if (ctx) {
        BN_CTX_free(ctx);
        ctx = nullptr;
    }
    if (p) {
        EC_POINT_free(p);
        p = nullptr;
    }
    return ret;
}
}
}
