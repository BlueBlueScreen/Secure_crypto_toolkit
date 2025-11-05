#pragma once
#include <openssl/types.h>
#include<vector>
#include<cstddef>
#include<cstdint>
#include<openssl/evp.h>
#include<stdexcept>
using namespace std;

namespace secure_crypto{
    //只提供sha256,md5和sha1的接口

    inline void hash_update(EVP_MD_CTX* ctx,const vector<uint8_t>&data){
        if(EVP_DigestUpdate(ctx, data.data(), data.size())!=1)
            throw runtime_error("secure_crypto::hash_update: Update failed");
    }

    inline void hash_update(EVP_MD_CTX* ctx, const std::string& s) {
    if (!s.empty() && EVP_DigestUpdate(ctx, s.data(), s.size()) != 1)
        throw std::runtime_error("secure_crypto::hash_update: Update failed");
    }


    inline vector<uint8_t> sha256(const vector<uint8_t>& data){
    //获取算法对象
    const EVP_MD* hash=EVP_sha256();
    //设置缓冲区
    vector<uint8_t> buf(EVP_MD_size(hash));
    unsigned int len=0;
    if(EVP_Digest(data.data(),data.size(),buf.data(),&len,hash,NULL)!=1)
        throw runtime_error("secure_crypto::sha256: Hash wrong");
    return buf;
    }

    template <typename...Args>
    vector<uint8_t> sha256_concat(const Args&... args){
        //获取算法对象
        const EVP_MD* hash=EVP_sha256();
        //生成上下文
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_MD_CTX_new failed");
        vector<uint8_t> md(EVP_MD_size(hash));
        unsigned int len=0;
        try{
            if(EVP_DigestInit_ex(ctx, hash, NULL)!=1)
                throw runtime_error("secure_crypto::sha256: Init error");
            //可变参数展开
           (hash_update(ctx,args),...);
            
           if(EVP_DigestFinal_ex(ctx, md.data(), &len)!=1){
                throw runtime_error("secure_crypto::sha256: DigestFinal error");
           }
           md.resize(len);
           EVP_MD_CTX_free(ctx);
           return md;
        }catch(...){
            EVP_MD_CTX_free(ctx);
            throw;
        }

    }

    inline vector<uint8_t> md5(const vector<uint8_t>& data){
    //获取算法对象
    const EVP_MD* hash=EVP_md5();
    //设置缓冲区
    vector<uint8_t> buf(EVP_MD_size(hash));
    unsigned int len=0;
    if(EVP_Digest(data.data(),data.size(),buf.data(),&len,hash,NULL)!=1)
        throw runtime_error("secure_crypto::md5: Hash wrong");
    return buf;
    }

    template <typename...Args>
    vector<uint8_t> md5_concat(const Args&... args){
        //获取算法对象
        const EVP_MD* hash=EVP_md5();
        //生成上下文
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_MD_CTX_new failed");
        vector<uint8_t> md(EVP_MD_size(hash));
        unsigned int len=0;
        try{
            if(EVP_DigestInit_ex(ctx, hash, NULL)!=1)
                throw runtime_error("secure_crypto::md5: Init error");
            //可变参数展开
           (hash_update(ctx,args),...);
            
           if(EVP_DigestFinal_ex(ctx, md.data(), &len)!=1){
                throw runtime_error("secure_crypto::md5: DigestFinal error");
           }
           md.resize(len);
           EVP_MD_CTX_free(ctx);
           return md;
        }catch(...){
            EVP_MD_CTX_free(ctx);
            throw;
        }

    }

    inline vector<uint8_t> sha1(const vector<uint8_t>& data){
    //获取算法对象
    const EVP_MD* hash=EVP_sha1();
    //设置缓冲区
    vector<uint8_t> buf(EVP_MD_size(hash));
    unsigned int len=0;
    if(EVP_Digest(data.data(),data.size(),buf.data(),&len,hash,NULL)!=1)
        throw runtime_error("secure_crypto::sha1: Hash wrong");
    return buf; 
}

    template <typename...Args>
    vector<uint8_t> sha1_concat(const Args&... args){
        //获取算法对象
        const EVP_MD* hash=EVP_sha1();
        //生成上下文
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("EVP_MD_CTX_new failed");
        vector<uint8_t> md(EVP_MD_size(hash));
        unsigned int len=0;
        try{
            if(EVP_DigestInit_ex(ctx, hash, NULL)!=1)
                throw runtime_error("secure_crypto::sha1: Init error");
            //可变参数展开
           (hash_update(ctx,args),...);
            
           if(EVP_DigestFinal_ex(ctx, md.data(), &len)!=1){
                throw runtime_error("secure_crypto::sha1: DigestFinal error");
           }
           md.resize(len);
           EVP_MD_CTX_free(ctx);
           return md;
        }catch(...){
            EVP_MD_CTX_free(ctx);
            throw;
        }

    }
}