#include "PaymentAddress.h"
#include "PaymentCode.h"
#include "bip47_common.h"


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
    privKey = privKey_t;
}

CPubKey PaymentAddress::getSendECKey()
{
    return getSendECKey(getSecretPoint());
}

CKey PaymentAddress::getReceiveECKey()
{
    return getReceiveECKey(getSecretPoint());
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
    vector<unsigned char> pubkeybytes = paymentCode.addressAt(index).getPubKey();
    
    secp256k1_pubkey pubKey ;
    secp256k1_context *context = OpenSSLContext::get_context();
    secp256k1_ec_pubkey_parse(context,&pubKey, pubkeybytes.data(), pubkeybytes.size());
    
    GroupElement ge;
    
//     pubkeybytes.push_back(pubkeybytes[0] == 0x02 ? 0 : 1);
//     pubkeybytes.push_back(0x0);
//     ge.deserialize(pubkeybytes.data() + 1);
    
    ge.deserialize(pubKey.data);
    
    return ge;
}

std::vector<unsigned char> PaymentAddress::hashSharedSecret() {

    std::vector<unsigned char> shardbytes = getSharedSecret().ECDHSecretAsBytes();
    LogPrintf("Hash Shared Secret: %s\n", HexStr(shardbytes));
    
    return shardbytes;
}

GroupElement PaymentAddress::get_sG(Scalar s) {
    sigma::Params* _ec_params = sigma::Params::get_default();
    return _ec_params->get_g() * s;
}

CPubKey PaymentAddress::getSendECKey(Scalar s)
{
    LogPrintf("getSendECKey:SecretPoint = %s\n", s.GetHex());
    
    GroupElement ecPoint = getECPoint();
    LogPrintf("getSendECKey:ecPoint = %s\n", ecPoint.GetHex());
    
    GroupElement sG = get_sG(s);
    LogPrintf("getSendECKey:sG = %s\n", sG.GetHex());
    GroupElement ecG = ecPoint + sG;
    LogPrintf("getSendECKey:ecG= %s\n", ecG.GetHex());
    LogPrintf("getSendECKey:buffersize required = %d\n", ecG.memoryRequired());

//     unsigned char buffer[34] = {0};
    secp256k1_pubkey pubKey ;
    ecG.serialize(pubKey.data);
    
    vector<unsigned char> pubkey_vch  = ecG.getvch();
    
    
    vector<unsigned char> pubkey_bytes(33);
    secp256k1_context *context = OpenSSLContext::get_context();
    size_t pubkey_size = 33;
    secp256k1_ec_pubkey_serialize(context, pubkey_bytes.data(), &pubkey_size, &pubKey, SECP256K1_EC_COMPRESSED);
    
    
    LogPrintf("getSendECKey:pubkey_bytes = %s size = %d\n", HexStr(pubkey_bytes), pubkey_size);
    
    CPubKey pkey;
    pkey.Set(pubkey_bytes.begin(), pubkey_bytes.end());
    
    
//     vector<unsigned char> pkeybytes(33);
//     pkeybytes[0] = buffer[32] == 0 ? 0x02 : 0x03;
//     Bip47_common::arraycopy(buffer, 0, pkeybytes, 1, 32);
//     pkey.Set(pkeybytes.begin(), pkeybytes.end());
    LogPrintf("Validate getSendECKey is %s\n", pkey.IsValid()? "true":"false");

    return pkey;
}

CKey PaymentAddress::getReceiveECKey(Scalar s)
{
    Scalar privKeyValue(privKey.data());
    Scalar newKeyS = privKeyValue + s;
    
    CKey pkey;
    
    vector<unsigned char> ppkeybytes = ParseHex(newKeyS.GetHex());
    pkey.Set(ppkeybytes.begin(), ppkeybytes.end(), true);
    LogPrintf( "getReceiveECKey validate key is %s\n", pkey.IsValid() ? "true":"false") ;
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













