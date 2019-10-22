#include "Bip47Wallet.h"
#include "Bip47Account.h"
#include "SecretPoint.h"
#include "Bip47Util.h"
#include "script/ismine.h"
#include "uint256.h"

/**
 * The default bip47 wallet file name and instance.
 * */
Bip47Wallet *pbip47WalletMain = NULL;
const char *DEFAULT_BIP47_WALLET_DAT = "bip47_wallet.dat";

Bip47Wallet::Bip47Wallet(string strWalletFileIn, string coinName, string seedStr): CWallet(strWalletFileIn)
{
    this->coinName = coinName;
    
}

Bip47Wallet::Bip47Wallet(string strWalletFileIn, string p_coinName, CExtKey masterExtKey): CWallet(strWalletFileIn),coinName(p_coinName)
{

    deriveAccount(masterExtKey);
    CBitcoinAddress notificationAddress = mBip47Accounts[0].getNotificationAddress();
    CScript notificationScript = GetScriptForDestination(notificationAddress.Get());
    if (!pwalletMain->HaveWatchOnly(notificationScript))
    {
        pwalletMain->AddWatchOnly(notificationScript);
    }
    LogPrintf("Bip47Wallet notification Address: %s\n", notificationAddress.ToString());
    
}

bool Bip47Wallet::initLoadBip47Wallet()
{
    LogPrintf("InitLoadBip47Wallet()\n");
    std::string bip47WalletFile = GetArg("-bip47wallet", DEFAULT_BIP47_WALLET_DAT);
    /**
     * @Todo set correct seed str to create bip47 wallet
     * */
    // Use MasterKeyId from HDChain as index for mintpool
    CKeyID masterKeyID = pwalletMain->GetHDChain().masterKeyID;
    if(!masterKeyID.IsNull())
    {
        CKey key;
        if(pwalletMain->GetKey(masterKeyID, key))
        {
            CExtKey masterKey;
            masterKey.SetMaster(key.begin(), key.size());
            Bip47Wallet *walletInstance = new Bip47Wallet(bip47WalletFile, "zcoin", masterKey);
            pbip47WalletMain = walletInstance;
            return true;
        }
    }
    return false;
    
}






PaymentCode Bip47Wallet::getPaymentCodeInNotificationTransaction(CTransaction tx) 
{
    PaymentCode paymentCode;
    vector<unsigned char> prvKeyBytes(mBip47Accounts[0].getNotificationPrivKey().key.begin(), mBip47Accounts[0].getNotificationPrivKey().key.end());
    BIP47Util::getPaymentCodeInNotificationTransaction(prvKeyBytes , tx, paymentCode);
    return paymentCode;
}

bool Bip47Wallet::savePaymentCode(PaymentCode paymentCode) 
{
    std::map<std::string, Bip47PaymentChannel>::iterator it = channels.find(paymentCode.toString());
    // If contains paymentcode
    if(it != channels.end()) {
        try {
            Bip47PaymentChannel paymentChannel = it->second;
            paymentChannel.generateKeys(this);
            return true;
        } catch (std::exception &e){
            LogPrint("savePaymentCode Error: in Bip47Wallet.cpp", "%s", e.what());
            return false;
        }
    } else { // if not
        Bip47PaymentChannel paymentChannel(paymentCode.toString());
        try {
            paymentChannel.generateKeys(this);
            channels.insert(make_pair(paymentCode.toString(), paymentChannel));
            return true;
        } catch (std::exception &e) {
            LogPrint("savePaymentCode Error: in Bip47Wallet.cpp", "%s", e.what());
            return false;
        }
    }
}


CBitcoinAddress Bip47Wallet::getAddressOfKey(CExtPubKey pkey)
{
    CBitcoinAddress address(pkey.pubkey.GetID());
    return address;
}

bool Bip47Wallet::generateNewBip47IncomingAddress(std::string strAddress) 
{
    std::map<std::string, Bip47PaymentChannel>::iterator it = channels.begin();
    while(it != channels.end()) 
    {
        Bip47PaymentChannel paymentChannel = it->second;
        std::list<Bip47Address> bip47Addresses = paymentChannel.getIncomingAddresses();
        std::list<Bip47Address>::iterator addit = bip47Addresses.begin();
        while (addit != bip47Addresses.end())
        {
            if(addit->getAddress().compare(strAddress) != 0) 
            {
                addit++;
                continue;
            }

            if(addit->isSeen()) 
            {
                return false;
            }

            int nextIndex = paymentChannel.getCurrentIncomingIndex() + 1;

            /**
             * @todo BIP47Util getReceiveAddress works.
             * */
            try
            {
                return true;
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
            return false;
        }
        
        it++;
    }
    return false;
}

Bip47PaymentChannel Bip47Wallet::getBip47PaymentChannelForAddress(std::string strAddress) 
{
    std::map<std::string, Bip47PaymentChannel>::iterator it = channels.begin();

    while(it != channels.end()) {
        Bip47PaymentChannel paymentChannel = it->second;
        std::list<Bip47Address> bip47Addresses = paymentChannel.getIncomingAddresses();
        std::list<Bip47Address>::iterator bip47Address = bip47Addresses.begin();
        while (bip47Address != bip47Addresses.end())
        {
            if( bip47Address->getAddress().compare(strAddress) == 0) {
                return paymentChannel;
            }
            bip47Address++;
        }
        
        it++;
    }
    return Bip47PaymentChannel();
}

string Bip47Wallet::getPaymentCodeForAddress(string address)
{

    if (channels.find(address) == channels.end()) {
        return "";
    }
    return channels.find(address)->second.getPaymentCode();
    
}

Bip47PaymentChannel Bip47Wallet::getBip47PaymentChannelForOutgoingAddress(std::string strAddress)
{
    std::map<std::string, Bip47PaymentChannel>::iterator it = channels.begin();

    while(it != channels.end()) {
        Bip47PaymentChannel paymentChannel = it->second;
        std::list<std::string> outgoingAddresses = paymentChannel.getOutgoingAddresses();
        std::list<std::string>::iterator outgoingAddress = outgoingAddresses.begin();
        while (outgoingAddress != outgoingAddresses.end())
        {
            if( outgoingAddress->compare(strAddress) == 0) {
                return paymentChannel;
            }
            outgoingAddress++;
        }
        
        it++;
    }
    return Bip47PaymentChannel();
}

Bip47PaymentChannel Bip47Wallet::getBip47PaymentChannelForPaymentCode(std::string paymentCode)
{
    std::map<std::string, Bip47PaymentChannel>::iterator it = channels.begin();

    while(it != channels.end()) 
    {
        Bip47PaymentChannel paymentChannel = it->second;
        if (paymentChannel.getPaymentCode().compare(paymentCode) == 0)
        {
            return paymentChannel;
        }
        it++;
    }

    return Bip47PaymentChannel();
}

CAmount Bip47Wallet::getValueOfTransaction(CTransaction tx)
{
    return tx.GetValueOut();
}

/**
 * @todo check vout address is contains my address
 * */
CAmount Bip47Wallet::getValueSentToMe(CTransaction tx)
{
    
    return 0;
}


CTransaction* Bip47Wallet::getSignedNotificationTransaction(CWalletTx &sendRequest, string paymentCode) {
    CommitTransaction(sendRequest);
    return (CTransaction*)&sendRequest;
}


bool Bip47Wallet::isToBIP47Address(CTransaction tx)
{
    return false;
}






