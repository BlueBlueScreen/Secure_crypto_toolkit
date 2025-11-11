#include "secure_crypto/hkdf.hpp"
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include<stdexcept>
using namespace std;

namespace secure_crypto{
        vector<uint8_t> hkdf_sha256(
        const vector<uint8_t>& ikm,
        size_t n,
        const vector<uint8_t>& salt,
        const vector<uint8_t>& info
    ){
    //指定算法对象
    EVP_KDF* kdf=EVP_KDF_fetch(NULL, "HKDF", NULL);
    //生成KDF专用上下文
    try{
        EVP_KDF_CTX* ctx=EVP_KDF_CTX_new(kdf);
        if(!ctx) runtime_error("secure_crypto::hkdf_sha256: EVP_KDF_CTX error");
        //还需要指定算法对象先
        const string digest="SHA256";
        int mode=EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
        OSSL_PARAM params[]={
            OSSL_PARAM_construct_utf8_string("digest",const_cast<char*>(digest.c_str()),0),
            OSSL_PARAM_construct_octet_string("salt", (void*)salt.data(), salt.size()),
            OSSL_PARAM_construct_octet_string("info", (void*)info.data(), info.size()),
            OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size()),
            OSSL_PARAM_END
        };


        //执行HKDF派生
        vector<uint8_t> key(n);
        if(EVP_KDF_derive(ctx, key.data(), n, params)!=1){
            throw runtime_error("secure_crypto::hkdf_sha256: EVP_KDF_derive fail");
        }

        //释放上下文
        EVP_KDF_free(kdf);
        return key;
    }catch(...){
        EVP_KDF_free(kdf);
        throw;
    }
    }

}