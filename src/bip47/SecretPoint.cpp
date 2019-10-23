#include "sigma/coin.h"
#include "SecretPoint.h"

SecretPoint::SecretPoint() {
}

SecretPoint::SecretPoint(std::vector<unsigned char> dataPrv, std::vector<unsigned char> dataPub)
{
    loadPrivateKey(dataPrv);
    loadPublicKey(dataPub);
}

CKey& SecretPoint::getPrivKey() {
    return privKey;
}

void SecretPoint::setPrivKey(CKey &v_privKey) {
    privKey = v_privKey;
}

secp256k1_pubkey& SecretPoint::getPubKey() {
    return pubKey;
}

void SecretPoint::setPubKey(secp256k1_pubkey &v_pubKey) {
    pubKey = v_pubKey;
}

std::vector<unsigned char> SecretPoint::ECDHSecretAsBytes(){
    return ECDHSecret();
}

bool SecretPoint::isShared(SecretPoint secret) {
    return equals(secret);
}

std::vector<unsigned char> SecretPoint::ECDHSecret() {
    std::vector<unsigned char> pubkey_hash(32, 0);
    secp256k1_context *context = OpenSSLContext::get_context();
    // We use secp256k1_ecdh instead of secp256k1_serialize_pubkey to avoid a timing channel.
    if (1 != secp256k1_ecdh(context, pubkey_hash.data(), &pubKey,privKey.begin())) {
        throw std::runtime_error("Unable to compute public key hash with secp256k1_ecdh.");
    }
    std::vector<unsigned char> hash(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(pubkey_hash.data(), pubkey_hash.size()).Finalize(hash.data());
    return hash;
}

bool SecretPoint::equals(SecretPoint &v_secret){
    string str1 = HexStr(ECDHSecretAsBytes());
    string str2 = HexStr(v_secret.ECDHSecretAsBytes());
    if(str1.compare(str2)==0)
        return true ;
    return false ;
}

void SecretPoint::loadPublicKey(std::vector<unsigned char> data) {
    secp256k1_context *context = OpenSSLContext::get_context();
    secp256k1_ec_pubkey_parse(context,&pubKey,data.data(),data.size());
}

void SecretPoint::loadPrivateKey(std::vector<unsigned char> data) {
    privKey.Set(data.begin(),data.end(),false);
}

bool SecretPoint::SelfTest(CWallet* wallet)
{
    CKey key1, key2;
    
    CPubKey pubkey1, pubkey2;
    
    
    if (!wallet->GetKeyFromPool(pubkey1))
    {
        LogPrintf("Cannot get Key from Pool 1\n");
        return false;
    }
    else
    {
        wallet->GetKey(pubkey1.GetID(), key1);
    }

    if (!wallet->GetKeyFromPool(pubkey2))
    {
        LogPrintf("Cannot get Key from Pool 2\n");
        return false;
    }
    else
    {
        wallet->GetKey(pubkey2.GetID(), key2);
    }

    std::vector<unsigned char> key1bytes(key1.begin(), key1.end());
    std::vector<unsigned char> key2bytes(key2.begin(), key2.end());
    
    std::vector<unsigned char> pubkey1bytes(pubkey1.begin(), pubkey1.end());
    std::vector<unsigned char> pubkey2bytes(pubkey2.begin(), pubkey2.end());
    
    SecretPoint scretp1(key1bytes, pubkey2bytes);
    SecretPoint scretp2(key2bytes, pubkey1bytes);
    return scretp1.equals(scretp2);
}

