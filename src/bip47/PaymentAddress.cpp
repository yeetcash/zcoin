#include "PaymentAddress.h"


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

PaymentAddress::~PaymentAddress()
{
}

SecretPoint PaymentAddress::sharedSecret()
{
    SecretPoint secP(privKey, paymentCode.addressAt(index).getPubKey());
    return secP;
}

void PaymentAddress::secretPoint() {
    
}


std::vector<unsigned char> PaymentAddress::hashSharedSecret() {

    return getSharedSecret().ECDHSecretAsBytes();
}

SecretPoint PaymentAddress::getSharedSecret() {

    return sharedSecret();
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

CPubKey PaymentAddress::getReceiveECKey()
{
    secretPoint();
    CKey privvkey;
    
    CPubKey ppkey;
    return ppkey;
}
