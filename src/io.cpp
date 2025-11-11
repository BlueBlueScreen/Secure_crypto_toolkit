#include<secure_crypto/io.hpp>
using namespace std;

namespace secure_crypto{
    vector<uint8_t> load_private_key_der_from_pem(const std::string& filepath){
        BIO* bio = nullptr;
        EVP_PKEY* sk = nullptr;
        BIO* mem_bio = nullptr;
        try{
        //只读模式
        bio=BIO_new_file(filepath.data(),"r");
        if(!bio) throw runtime_error("secure_crypto:load_private_key_der_from_pem: file path wrong");
        //尝试读取私钥，如果文件类型不对或者是公钥类型则报错
        sk= PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
        if(!sk) throw runtime_error("secure_crypto:load_private_key_der_from_pem: file type wrong");
        //检查类型
        int id=EVP_PKEY_get_id(sk);
        //进行序列化操作，将sk转换格式
        mem_bio=BIO_new(BIO_s_mem());
        if(!mem_bio) throw runtime_error("secure_crypto:load_private_key_der_from_pem: BIO_new error");
        if(i2d_PrivateKey_bio(mem_bio,sk)!=1) throw runtime_error("secure_crypto:load_private_key_der_from_pem: i2d_PrivateKey_bio error");
        //提取字节
        char* data;
        long len=BIO_get_mem_data(mem_bio,&data);
        if(len<=0||!data) throw runtime_error("secure_crypto:load_private_key_der_from_pem: BIO_get_mem_data error");

        vector<uint8_t> der(data, data + len);
        BIO_free(mem_bio);
        BIO_free(bio);
        EVP_PKEY_free(sk);
        return der;
    }
    catch(...){
        if (bio) BIO_free(bio);
        if (sk) EVP_PKEY_free(sk);
        if (mem_bio) BIO_free(mem_bio);
        throw;
    } 
}
    vector<uint8_t> load_public_key_der_from_pem(const std::string& filepath){
        BIO* bio=nullptr;
        EVP_PKEY* pk=nullptr;
        BIO* mem_bio=nullptr;
        try{
            bio=BIO_new_file(filepath.data(),"r");
            if(!bio) throw runtime_error("secure_crypto:load_public_key_der_from_pem: file type wrong");
            //先尝试直接读取公钥
            pk=PEM_read_bio_PUBKEY(bio,NULL,NULL,NULL);
            //如果没能读取公钥对象，那就直接读取私钥对象
            if(!pk){
            //没读成功的话重置这个对象，读取私钥来进行操作
                BIO_reset(bio);
                pk=PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
                if(!pk) throw runtime_error("secure_crypto:load_public_key_der_from_pem: read key error");
            }
            //同样检查类型，不过目前还不知道这个类型检查起到了什么作用
            int id=EVP_PKEY_get_id(pk);
            //开始进行序列化操作
            char* data;
            mem_bio=BIO_new(BIO_s_mem());
            if(!mem_bio) throw runtime_error("secure_crypto:load_public_key_der_from_pem: BIO_new error");
            if(i2d_PUBKEY_bio(mem_bio,pk)!=1) throw runtime_error("secure_crypto:load_public_key_der_from_pem: i2d_PUBKEY_bio error");
            long len=BIO_get_mem_data(mem_bio,&data);
            if(len<=0||!data) throw runtime_error("secure_crypto:load_private_key_der_from_pem: BIO_get_mem_data error");
            vector<uint8_t> der(data,data+len);
            BIO_free(bio);
            EVP_PKEY_free(pk);
            BIO_free(mem_bio);
            return der;

        }catch(...){
            if (bio) BIO_free(bio);
            if (pk) EVP_PKEY_free(pk);
            if (mem_bio) BIO_free(mem_bio);
            throw;
        }
    }
}