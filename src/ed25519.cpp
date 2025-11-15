#include<secure_crypto/ed25519.hpp>
using namespace std;

namespace secure_crypto{
    void sign_keygen(const string& sk_path,const string& pk_path){
        //指定曲线为ED25519曲线
        EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
        EVP_PKEY* pkey=nullptr;
        try{
            if(!ctx) throw runtime_error("secure_crypto::sign_keygen:EVP_PKEY_CTX_new_id fail");
            if(EVP_PKEY_keygen_init(ctx)!=1)
                throw runtime_error("secure_crypto::sign_keygen:EVP_PKEY_keygen_init fail");
            if(EVP_PKEY_keygen(ctx,&pkey)!=1)
                throw runtime_error("secure_crypto::sign_keygen:EVP_PKEY_keygen fail");
            //保存公私钥
            write_private_key(pkey,sk_path);
            write_public_key(pkey,pk_path);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);     
        }catch(...){
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw;
        }
    }
    vector<uint8_t> sign(const string& sk_path, const string& message){
        //先读取私钥
        vector<uint8_t> ecdh_sk=load_private_key_der_from_pem(sk_path);
        EVP_PKEY* sk=nullptr;
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        
        try{
            if (!ctx) 
            throw runtime_error("secure_crypto::sign: EVP_MD_CTX_new failed");
            //对私钥进行反序列化
            const unsigned char* p=ecdh_sk.data();
            d2i_AutoPrivateKey(&sk,&p,ecdh_sk.size());
            if (!sk) 
            throw runtime_error("secure_crypto::sign: d2i_AutoPrivateKey failed");
            //进行初始化
            if(EVP_DigestSignInit(ctx,NULL,NULL,NULL,sk)!=1)
            throw runtime_error("secure_crypto:sign: EVP_DigestSignInit fail");

            //将Message转换为字节串形式来进行签名
            vector<uint8_t> msg(message.begin(),message.end());
            //签名的步骤和ECDH派生的步骤类似，都是先调用一次取长度，再调用一次进行签名
            size_t siglen;
            if(EVP_DigestSign(ctx,NULL,&siglen,msg.data(),msg.size())!=1)
                throw runtime_error("secure_crypto::sign: EVP_DigestSign fail");
            vector<uint8_t> signature(siglen);
            if(EVP_DigestSign(ctx,signature.data(),&siglen,msg.data(),msg.size())!=1)
                throw runtime_error("secure_crypto::sign: EVP_DigestSign fail");
            EVP_PKEY_free(sk);
            EVP_MD_CTX_free(ctx);
            return signature;
    }catch(...){
        EVP_PKEY_free(sk);
        EVP_MD_CTX_free(ctx);
        throw;
    }
}
    bool verify(vector<uint8_t>& signature,const string& pk_path,const string& message){
        //先读取私钥
        vector<uint8_t> ecdh_pk=load_public_key_der_from_pem(pk_path);
        EVP_PKEY* pk=nullptr;
        EVP_MD_CTX* ctx=EVP_MD_CTX_new();
        try{
            //检查上下文初始化是否成功
            if(!ctx) throw runtime_error("secure_crypto::verify: CTX init fail");
            //对公钥进行反序列化
            const unsigned char* p=ecdh_pk.data();
            d2i_PUBKEY(&pk,&p,ecdh_pk.size());
            if (!pk) 
            throw runtime_error("secure_crypto::verify: d2i_PUBKEY failed");
            //将Message转换为字节串形式来进行验证签名
            vector<uint8_t> msg(message.begin(),message.end());
            //初始化验签函数
            if(EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,pk)!=1)
            throw runtime_error("secure_crypto::verify: EVP_DigestVerifyInit fail");
            int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(), msg.data(), msg.size());
            if (ret < 0) {
                throw runtime_error("secure_crypto::verify: EVP_DigestVerify error");
            }
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pk);
            return ret==1;
        }catch(...){
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pk);
            throw;
        }
        
    }
}