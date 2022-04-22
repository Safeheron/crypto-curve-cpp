#ifndef _SAFEHERON_MCL_WRAPPER_H_
#define _SAFEHERON_MCL_WRAPPER_H_

#include <mcl/bls12_381.hpp>
#include "safeheron/crypto-bn/bn.h"

typedef mcl::bls12::G1  BLS_G1;
typedef mcl::bls12::G2  BLS_G2;
typedef mcl::bls12::Fp12  BLS_E;

class MclInit{
public:
    MclInit(){
        mcl::bls12::initPairing(mcl::BLS12_381);
    }
    ~MclInit(){};
};

bool mcl_Init();
bool mcl_hashAndMapToG1(BLS_G1& g1,const void *buf, size_t bufSize);
bool mcl_hashAndMapToG2(BLS_G2& g2,const void *buf, size_t bufSize);

bool mcl_XYInitG1(BLS_G1& g1,const safeheron::bignum::BN &x, const safeheron::bignum::BN &y);
bool mcl_XYInitG2(BLS_G2& g2,const safeheron::bignum::BN &x, const safeheron::bignum::BN &y);

bool mcl_G1Valid(const safeheron::bignum::BN &x,const safeheron::bignum::BN &y);
bool mcl_G2Valid(const safeheron::bignum::BN &x,const safeheron::bignum::BN &y);

bool mcl_G1Neg(BLS_G1& g1,const BLS_G1& p);
bool mcl_G2Neg(BLS_G2& g2,const BLS_G2& p);

bool mcl_G1Add(BLS_G1& g1,const BLS_G1& p,const BLS_G1& q);
bool mcl_G2Add(BLS_G2& g2,const BLS_G2& p,const BLS_G2& q);

bool mcl_G1Mul(BLS_G1& g1,const BLS_G1& p,const safeheron::bignum::BN &bn);
bool mcl_G2Mul(BLS_G2& g2,const BLS_G2& p,const safeheron::bignum::BN &bn);

bool mcl_G1MulCT(BLS_G1& g1,const BLS_G1& p,const safeheron::bignum::BN &bn);
bool mcl_G2MulCT(BLS_G2& g2,const BLS_G2& p,const safeheron::bignum::BN &bn);

bool mcl_GetG1X(safeheron::bignum::BN &bn, BLS_G1 g1);
bool mcl_GetG1Y(safeheron::bignum::BN &bn, BLS_G1 g1);

bool mcl_GetG2X(safeheron::bignum::BN &bn, BLS_G2 g2);
bool mcl_GetG2Y(safeheron::bignum::BN &bn, BLS_G2 g2);

bool mcl_Pairing(BLS_E& f, const BLS_G1& P, const BLS_G2& Q);

bool mcl_VerifyG1G2(const BLS_G1 &g,const BLS_G2 &sig, const BLS_G1 &pub, const BLS_G2 &hmsg);
bool mcl_VerifyG2G1(const BLS_G2 &g,const BLS_G1 &sig, const BLS_G2 &pub, const BLS_G1 &hmsg);

std::string  mcl_SerializeToHexStr(BLS_G1 P);
std::string  mcl_SerializeToHexStr(BLS_G2 P);


#endif //_SAFEHERON_MCL_WRAPPER_H_