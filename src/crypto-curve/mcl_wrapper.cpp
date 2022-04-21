#include "mcl_wrapper.h"
#include <iostream>
using namespace std;


bool mcl_BNToFp(mcl::bls12::Fp & f,const safeheron::bignum::BN &bn){
    //if(bn.BitLength() > mcl::bls12::MCL_MAX_FP_BIT_SIZE
    string bnstr;
    bn.ToHexStr(bnstr);
    f.setStr(bnstr,16);
    return true;
}
bool mcl_BNToFp2(mcl::bls12::Fp2 & f,const safeheron::bignum::BN &bn){
    //if(bn.BitLength() > mcl::bls12::MCL_MAX_FP_BIT_SIZE
    string bnstr;
    bn.ToHexStr(bnstr);
    f.deserializeHexStr(bnstr);
    return true;
}

////////////////////////////////////////////////////////////////////
bool mcl_Init(){
    mcl::bls12::initPairing(mcl::BLS12_381);
    return true;
}
///////////////////////////////////////////////////////////////////
bool mcl_RandomInitG1(BLS_G1& g1,const void *buf, size_t bufSize){
    mcl::bls12::hashAndMapToG1(g1, buf,bufSize);
    return true;
}
bool mcl_RandomInitG2(BLS_G2& g2,const void *buf, size_t bufSize){
    mcl::bls12::hashAndMapToG2(g2, buf,bufSize);
    return true;
}
bool mcl_XYInitG1(BLS_G1& g1,const safeheron::bignum::BN &x, const safeheron::bignum::BN &y){
    mcl::bls12::Fp fx;
    mcl::bls12::Fp fy;
    mcl_BNToFp(fx,x);
    mcl_BNToFp(fy,y);
    g1.clear();
    g1.set(fx,fy);
    return true;
}
bool mcl_XYInitG2(BLS_G2& g2,const safeheron::bignum::BN &x, const safeheron::bignum::BN &y){
    mcl::bls12::Fp2 fx;
    mcl::bls12::Fp2 fy;
    mcl_BNToFp2(fx,x);
    mcl_BNToFp2(fy,y);
    g2.clear();
    g2.set(fx,fy);
    return true;
}

///////////////////////////////////////////////////////////////////

bool mcl_G1Neg(BLS_G1& g1,const BLS_G1& p){
    mcl::bls12::G1::neg(g1,p);
    return true;
}
bool mcl_G2Neg(BLS_G2& g2,const BLS_G2& p){
    mcl::bls12::G2::neg(g2,p);
    return true;
}

bool mcl_G1Add(BLS_G1& g1,const BLS_G1& p,const BLS_G1& q){
    mcl::bls12::G1::add(g1,p,q);
    return true;
}
bool mcl_G2Add(BLS_G2& g2,const BLS_G2& p,const BLS_G2& q){
    mcl::bls12::G2::add(g2,p,q);
    return true;
}
bool mcl_G1Mul(BLS_G1& g1,const BLS_G1& p,const safeheron::bignum::BN &bn){
    //TODO... BN maybe big then fr
    mcl::bls12::Fp q;
    mcl_BNToFp(q,bn);
    mcl::bls12::G1::mul(g1,p,q);
    return true;
}
bool mcl_G2Mul(BLS_G2& g2,const BLS_G2& p,const safeheron::bignum::BN &bn){
    //TODO... BN maybe big then fr
    mcl::bls12::Fp q;
    mcl_BNToFp(q,bn);
    mcl::bls12::G2::mul(g2,p,q);
    return true;
}

bool mcl_G1Valid(const safeheron::bignum::BN &x,const safeheron::bignum::BN &y)
{
    mcl::bls12::Fp fx;
    mcl::bls12::Fp fy;
    mcl_BNToFp(fx,x);
    mcl_BNToFp(fy,y);
    BLS_G1 testg1(fx,fy);
    return testg1.isValid();
}
bool mcl_G2Valid(const safeheron::bignum::BN &x,const safeheron::bignum::BN &y)
{
    mcl::bls12::Fp2 fx;
    mcl::bls12::Fp2 fy;
    mcl_BNToFp2(fx,x);
    mcl_BNToFp2(fy,y);
    BLS_G2 testg2(fx,fy);
    return testg2.isValid();
}

bool mcl_GetG1X(safeheron::bignum::BN &bn, BLS_G1 g1)
{
    g1.normalize();
    bn = safeheron::bignum::BN::FromHexStr(g1.x.getStr(16));
    return true; 
}
bool mcl_GetG1Y(safeheron::bignum::BN &bn, BLS_G1 g1)
{
    g1.normalize();
    bn = safeheron::bignum::BN::FromHexStr(g1.y.getStr(16));
    return true; 
}

bool mcl_GetG2X(safeheron::bignum::BN &bn, BLS_G2 g2)
{
    g2.normalize();
    bn = safeheron::bignum::BN::FromHexStr(g2.x.serializeToHexStr());
    return true; 
}
bool mcl_GetG2Y(safeheron::bignum::BN &bn, BLS_G2 g2)
{
    g2.normalize();
    bn = safeheron::bignum::BN::FromHexStr(g2.y.serializeToHexStr());
    return true; 
}

bool mcl_Pairing(BLS_E& f, const BLS_G1& P, const BLS_G2& Q)
{
    mcl::bls12::pairing(f,P,Q);
    return true;
}
