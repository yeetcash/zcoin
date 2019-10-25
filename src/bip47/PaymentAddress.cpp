#include "PaymentAddress.h"
#include "PaymentCode.h"


PaymentAddress::PaymentAddress()
{
    // paymentCode = nullptr;
    // privKey = nullptr;
    index = 0;

}
PaymentAddress::PaymentAddress(PaymentCode paymentCode_t)
{
    paymentCode = paymentCode_t;
    index = 0;
    // privKey = nullptr;
}

PaymentCode PaymentAddress::getPaymentCode() {
    return paymentCode;
}

void PaymentAddress::setPaymentCode(PaymentCode paymentCode_t) {
    paymentCode = paymentCode_t;
}
int PaymentAddress::getIndex() {
    return index;
}

void PaymentAddress::setIndex(int index_t) {
    index = index_t;
}

vector<unsigned char> PaymentAddress::getPrivKey() {
    return privKey;
}

void PaymentAddress::setIndexAndPrivKey(int index_t, vector<unsigned char> privKey_t) {
    index = index_t;
    privKey = privKey_t;
}

void PaymentAddress::setPrivKey(vector<unsigned char> privKey_t) {
    privKey = privKey;
}

CPubKey PaymentAddress::getSendECKey()
{
    hashSharedSecret();
    
//     ecPoint
    
    paymentCode.addressAt(index).getPubKey();
    
    CPubKey ppkey;
    
    CKey privateK;
    CPrivKey privatekk;
    
//     privateK.SetPrivKey()
    
    
    return ppkey;
}

CPubKey PaymentAddress::getReceiveECKey()
{
    hashSharedSecret();
    this->privKey;
    
    CPubKey ppkey;
    return ppkey;
}

GroupElement PaymentAddress::get_sG()
{
    return get_sG(getSecretPoint());
}

SecretPoint PaymentAddress::getSharedSecret() {
    return sharedSecret();
}

Scalar PaymentAddress::getSecretPoint() {
    return secretPoint();
}

GroupElement PaymentAddress::getECPoint() {
    CPubKey pubkey;
    vector<unsigned char> pubkeybytes = paymentCode.addressAt(index).getPubKey();
    pubkey.Set(pubkeybytes.begin(), pubkeybytes.end());
    
    GroupElement ge;
    ge.deserialize(pubkeybytes.data());
    return ge;
}

std::vector<unsigned char> PaymentAddress::hashSharedSecret() {

    uint256 hashval, hashval2;
    
    std::vector<unsigned char> shardbytes = getSharedSecret().ECDHSecretAsBytes();
    Scalar scal(shardbytes.data());
    sigma::Params* _ec_params = sigma::Params::get_default();
    GroupElement sg = _ec_params->get_g() * scal;
    
    

    return shardbytes;
}

GroupElement PaymentAddress::get_sG(Scalar s) {
    sigma::Params* _ec_params = sigma::Params::get_default();
    return _ec_params->get_g() * s;
}

CPubKey PaymentAddress::getSendECKey(Scalar s)
{
    GroupElement ecPoint = getECPoint();
    GroupElement sG = get_sG(s);
    GroupElement ecG = ecPoint + sG;
    
    CPubKey pkey;
    return pkey;
}

SecretPoint PaymentAddress::sharedSecret()
{
    SecretPoint secP(privKey, paymentCode.addressAt(index).getPubKey());
    return secP;
}

secp_primitives::Scalar PaymentAddress::secretPoint()
{
    return secp_primitives::Scalar(hashSharedSecret().data());
    
}













