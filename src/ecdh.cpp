#include<secure_crypto/ecdh.hpp>

using namespace std;
namespace secure_crypto{

    void ecdh_create_key(const string& sk_path,const string& pk_path){
        //创建上下文
        EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
        EVP_PKEY* pkey=nullptr;
        try{
        //密钥生成初始化
        if(EVP_PKEY_keygen_init(ctx)!=1)
            throw runtime_error("secure_crypto::ecdh_create_key: EVP_PKEY_keygen_init fail");
        //设置完之后就该生成了

        if(EVP_PKEY_keygen(ctx,&pkey)!=1)
            throw runtime_error("secure_crypto::ecdh_create_key: EVP_PKEY_keygen fail");
        //保存私钥
        write_private_key(pkey,sk_path);
        //保存公钥
        write_public_key(pkey,pk_path);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        }catch(...){
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw;
        }
    }

    
    
    
    vector<uint8_t> ecdh_derive_key(const string& sk_path,const string& pk_path)
    {
        //先读取本地的私钥
        vector<uint8_t> ecdh_sk=load_private_key_der_from_pem(sk_path);
        //再读取远端传来的公钥
        vector<uint8_t> ecdh_pk=load_public_key_der_from_pem(pk_path);
        //接下来就是要将这两个数据反序列化为EVP格式了
        const unsigned char *p_sk=ecdh_sk.data();
        const unsigned char *p_pk=ecdh_pk.data();
        EVP_PKEY* sk=nullptr;
        EVP_PKEY* pk=nullptr;
        EVP_PKEY_CTX* ctx=nullptr;
        try{
        sk = d2i_AutoPrivateKey(NULL, &p_sk, ecdh_sk.size());
        pk = d2i_PUBKEY(&pk,&p_pk,ecdh_pk.size());
        if(!sk) throw runtime_error("secure_crypto::ecdh_derive_key: d2i_PrivateKey fail");
        if(!pk) throw runtime_error("secure_crytpo::ecdh_derive_key: d2i_PUBKEY fail");
        //之后通过ECDH自带的密钥派生函数来生成共享密钥
        ctx=EVP_PKEY_CTX_new(sk,NULL);
        //初始化密钥派生函数
        if(EVP_PKEY_derive_init(ctx)!=1)
            throw runtime_error("secure_crypto::ecdh_derive_key: EVP_PKEY_derive_init fail");
        //设置远端密钥
        if(EVP_PKEY_derive_set_peer(ctx,pk)!=1)
            throw runtime_error("secure_crypto::ecdh_derive_key: EVP_PKEY_derive_set_peer fail");
        //两次调用EVP_PKEY_derive函数，第一次安全获取可变长度，第二次获取密钥
        size_t keylen;
        if(EVP_PKEY_derive(ctx,NULL,&keylen)!=1)
            throw runtime_error("secure_crypto::ecdh_derive_key: EVP_PKEY_derive for keylen fail");
        vector<uint8_t> session_key(keylen);
        if(EVP_PKEY_derive(ctx,session_key.data(),&keylen)!=1)
            throw runtime_error("secure_crypto::ecdh_derive_key: EVP_PKEY_derive for key fail");
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pk);
        EVP_PKEY_free(sk);
        return session_key;
        }
        catch(...){
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pk);
            EVP_PKEY_free(sk);
            throw;
        }
    
    }

}