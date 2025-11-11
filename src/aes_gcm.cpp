
#include <openssl/evp.h>
#include<secure_crypto/aes_gcm.hpp>
#include <stdexcept>
using namespace std;

namespace secure_crypto{
        tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> aes_gcm_encrypt(
        const vector<uint8_t>& key, 
        const string& plaintext,  
        const vector<uint8_t>& aad 
    )
    {
        //首先检查密钥长度
        if(key.size()!=16&&key.size()!=32){
            throw runtime_error("secure_crypto::aes_gcm_128_encrypt: Wrong key length");
        }
        //将string类型的明文转换为字节串类型
        vector<uint8_t> ptext(plaintext.begin(),plaintext.end());

        //获取算法对象
         const EVP_CIPHER* cipher=key.size()==16?EVP_aes_128_gcm():EVP_aes_256_gcm();
        //创建一个新的上下文
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw runtime_error("secure_crypto::aes_gcm_encrypt: EVP_CIPHER_CTX_new failed");
        try{
        //初始化加密函数
        vector<uint8_t> nonce=random_bytes(12);
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, key.data(), nonce.data()) != 1)
                throw runtime_error("secure_crypto::aes_gcm_encrypt: EncryptInit_ex (set key/iv) failed");
        //开始加密明文
        //可能需要处理附加数据
        if(!aad.empty()){
            int aad_outlen;
            if(EVP_EncryptUpdate(ctx, NULL, &aad_outlen, aad.data(), aad.size())!=1)
                throw runtime_error("secure_crypto::aes_gcm_encrypt: Update AAD failed");
        }
        vector<uint8_t> out(ptext.size()+EVP_CIPHER_block_size(cipher)); //输出密文的缓冲区，大小至少要覆盖明文和一个分组的长度
        int outlen=0; //输出密文的长度
        int cipherlen=0; //密文的总长度（可能需要多次处理）
        if(EVP_EncryptUpdate(ctx, out.data(), &outlen, ptext.data(), ptext.size())!=1)
            throw runtime_error("secure_crypto::aes_gcm_encrypt: Encryption Error");
        cipherlen+=outlen;

        //结束加密
        outlen=0;
        if(EVP_EncryptFinal_ex(ctx, out.data()+cipherlen, &outlen)!=1)
         throw runtime_error("secure_crypto::aes_gcm_encrypt: Final Encryption Error");
        cipherlen+=outlen;

        //获取tag
        vector<uint8_t> tag(16);
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())!=1)
            throw runtime_error("secure_crypto::aes_gcm_encrypt: Get tag error");
        
        //截断缓冲区输出到正常长度
        out.resize(cipherlen);
        //释放ctx，防止内存泄露
        EVP_CIPHER_CTX_free(ctx);
        return make_tuple(out,tag,nonce);
        
    }catch(...){
        //try catch 保证即使出错，ctx也可以正常释放，防止内存泄露
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    }

    
    string aes_gcm_decrypt(
        const vector<uint8_t>& key,
        tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple,
        const vector<uint8_t>& aad
    ){
        //首先获取解密必要的信息进行检查
        auto [cipher,tag,nonce]=cipher_tuple;
        if(tag.size()!=16||nonce.size()!=12){
            throw runtime_error("secure_crypto::aes_gcm_decrypt: Wrong tag or nonce data");
        }
        if(key.size()!=16&&key.size()!=32){
            throw runtime_error("secure_crypto::aes_gcm_128_decrypt: Wrong key length");
        }

        //根据密钥长度选择解密对象
        const EVP_CIPHER* cipher_type=key.size()==16?EVP_aes_128_gcm():EVP_aes_256_gcm();

        //创建一个新的上下文
        EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
        if(!ctx) throw runtime_error("secure_crypto::aes_gcm_decrypt: EVP_CIPHER_CTX_new failed");
        try{
        //进行初始化
        if(EVP_DecryptInit_ex(ctx,cipher_type,NULL,key.data(),nonce.data())!=1)
            throw runtime_error("secure_crypto::aes_gcm_decrypt: EVP_DecryptInit_ex failed");
        //处理附加数据
        if(!aad.empty()){
            int aad_in=0;
            if(EVP_DecryptUpdate(ctx, NULL, &aad_in, aad.data(), aad.size())!=1)
                throw runtime_error("secure_crypto::aes_gcm_decrypt: Update AAD failed");
        }
        //进行解密操作
        int len=0;
        int ptext_len=0;
        vector<uint8_t> ptext(cipher.size()+EVP_CIPHER_get_block_size(cipher_type));
        if(EVP_DecryptUpdate(ctx,ptext.data(),&len,cipher.data(),cipher.size())!=1)
            throw runtime_error("secure_crypto::aes_gcm_decrypt: Update cipher failed");
        ptext_len+=len;
        //tag必须在调用EVP_DecryptFinal_ex之前处理，在update前后都可以
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())!=1)
            throw runtime_error("secure_crypto::aes_gcm_decrypt: Tag wrong");
        //结束解密
        len=0;
        if(EVP_DecryptFinal_ex(ctx, ptext.data()+ptext_len, &len)!=1)
            throw runtime_error("secure_crypto::aes_gcm_decrypt: Decrypt cipher failed");
        ptext_len+=len;


        //截断缓冲区输出到正常长度
        ptext.resize(ptext_len);
        //释放上下文
        EVP_CIPHER_CTX_free(ctx);
        string res(ptext.begin(),ptext.end());
        return res;
        }catch(...){
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }

    }

}

