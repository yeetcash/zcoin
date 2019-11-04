#ifndef BIP47CHANNEL_H
#define BIP47CHANNEL_H
#include "bip47_common.h"
#include "Bip47Address.h"
#include <string>
#include "serialize.h"
#include "streams.h"

class CWallet;

class Bip47PaymentChannel {
    private:
     static string TAG ;

     static int STATUS_NOT_SENT ;
     static int STATUS_SENT_CFM ;
     static int LOOKAHEAD ;

     string paymentCode;
     string label;
     std::list<Bip47Address> incomingAddresses ;
     std::list<string> outgoingAddresses ;
     int status;
     int currentOutgoingIndex ;
     int currentIncomingIndex ;

    // private static final Logger log = LoggerFactory.getLogger(Bip47PaymentChannel.class);
    public:
        Bip47PaymentChannel() ;
        Bip47PaymentChannel(string v_paymentCode);
        Bip47PaymentChannel(string v_paymentCode, string v_label) ;
        string getPaymentCode() ;
        void setPaymentCode(string pc);
        std::list<Bip47Address>& getIncomingAddresses() ;
        int getCurrentIncomingIndex() ;
        void generateKeys(CWallet *bip47Wallet) ;
        Bip47Address* getIncomingAddress(string address) ;
        void addNewIncomingAddress(string newAddress, int nextIndex) ;
        string getLabel() ;
        void setLabel(string l) ;
        std::list<string>& getOutgoingAddresses() ;
        bool isNotificationTransactionSent() ;
        void setStatusSent() ;
        int getCurrentOutgoingIndex() ;
        void incrementOutgoingIndex() ;
        void addAddressToOutgoingAddresses(string address) ;
        void setStatusNotSent() ;
        
        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
            std::string outgoingS;
            std::list<string>::iterator out_it;
            for (out_it = outgoingAddresses.begin(); out_it != outgoingAddresses.end(); ++out_it)
            {
                outgoingS += *out_it;
                if(out_it != outgoingAddresses.end())
                    outgoingS += '\n';
            }
            
            
            std::list<Bip47Address>::iterator in_it;
            std::string inaddressesS;
            for(in_it = incomingAddresses.begin(); in_it != incomingAddresses.end(); ++ in_it)
            {
                CDataStream dss(SER_DISK, CLIENT_VERSION);
                dss << *in_it;
                dss >> inaddressesS;
                if(in_it != incomingAddresses.end())
                {
                    inaddressesS += '\n';
                }
            }
            
                
            READWRITE(paymentCode);
            READWRITE(label);
            READWRITE(status);
            READWRITE(currentIncomingIndex);
            READWRITE(currentOutgoingIndex);
            READWRITE(inaddressesS);
            READWRITE(outgoingS);
            
            if (ser_action.ForRead())
            {
                READWRITE(nVersion);
                std::stringstream ss(outgoingS);
                std::string to;
                if(!outgoingS.empty())
                {
                    while(std::getline(ss, to, '\n'))
                    {
                        outgoingAddresses.push_back(to);
                    }
                }
                
                std::stringstream inss(inaddressesS);
                std::string ins;
                if(!inaddressesS.empty())
                {
                    while(std::getline(inss, ins, '\n'))
                    {
                        CDataStream dss(SER_DISK, CLIENT_VERSION);
                        dss << ins;
                        Bip47Address b47ad;
                        dss >> b47ad;
                        incomingAddresses.push_back(b47ad);
                    }
                }
                
                
            }
        }
        
};

#endif
