#ifndef COMMON_H
#define COMMON_H
#include <iostream>
#include <list>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <openssl/sha.h>
#include "uint256.h"
#include "util.h"
    typedef std::string  String;
    typedef bool boolean;
    #define null    nullptr  
    class Bip47_common{
        public:
        static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,unsigned char* dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const unsigned char *source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
        static unsigned char* arraycopy(const std::vector<unsigned char> &source_arr,int sourcePos,std::vector<unsigned char> &dest_arr, int destPos, int len);
        static unsigned char* copyOfRange(const std::vector<unsigned char> &original, int from, int to,std::vector<unsigned char> &result) ;
        static boolean doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result);
    };
    #define HARDENED_BIT    0x80000000
    // const uint32_t HARDENED_BIT = 0x80000000;
#endif