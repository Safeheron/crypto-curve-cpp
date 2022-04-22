//
// Created by guoyi on 2022/4/18.
//

#include "bls12381.h"
#include "exception/safeheron_exceptions.h"
#include "mcl_wrapper.h"

using safeheron::exception::LocatedException;

namespace safeheron{
namespace curve {
namespace bls12_381 {
    
/*
	BLS signature:
	Pairing: e : G1 x G2 -> GT
    (using G1 for public keys,using G2 for signatures)
    g1      : base point of G1
    priv    : secret key  Fr
    pub     : public key  G1   
    msg     : sign message
    H       : {str} -> G2 
	sig     : signature of msg:  priv * H(msg)
	verify  : e(g1, H(msg)) = e(pub, sig)
	(swap G1 and G2 if ETH2)
*/

bool blsGetPublicKey(const CurveType pub_type,CurvePoint &pub, const safeheron::bignum::BN &priv)
{
    if( pub.GetCurveType() != pub_type){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1);
    }

    const curve::Curve *curv = curve::GetCurveParam(pub_type);
    pub = curv->g * priv;
    return true;
}
bool blsSign(const CurveType sig_type,CurvePoint &sig, const safeheron::bignum::BN &priv, const void *msg, size_t len)
{
    if( sig.GetCurveType() != sig_type){
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1);
    }

    const curve::Curve *curv = curve::GetCurveParam(sig_type);
    sig.HashAndMapToG(msg,len);
    sig = sig * priv;
    return true;
}
bool blsVerify(const CurveType pub_type,const CurveType sig_type,const CurvePoint &sig, const CurvePoint &pub, const void *msg, size_t len)
{
    if(pub.IsInfinity()) return 0;
    CurvePoint hm(sig_type);
	hm.HashAndMapToG(msg, len);

    const curve::Curve *curvG = curve::GetCurveParam(pub_type);
    //e(g1,sig) == e(pub,hm);
    bool ret = false;
    if(pub_type == CurveType::BLSG1){
        ret = mcl_VerifyG1G2(curvG->g.getBLSG1(),sig.getBLSG2(),pub.getBLSG1(),hm.getBLSG2());
    }else{
        ret = mcl_VerifyG2G1(curvG->g.getBLSG2(),sig.getBLSG1(),pub.getBLSG2(),hm.getBLSG1());
    }
    return ret;
}


}
}
}
