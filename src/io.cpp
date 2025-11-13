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
            if(len<=0||!data) throw runtime_error("secure_crypto:load_public_key_der_from_pem: BIO_get_mem_data error");
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
    vector<uint8_t> load_file_as_bytes(const std::string& filepath){
        ifstream file(filepath,ios::binary);
        if(!file) throw runtime_error("secure_crypto::load_file_as_bytes: file initiate fail");

        //获取文件大小
        file.seekg(0,ios::end);
        streampos pos = file.tellg();
        if (pos < 0) {
            throw runtime_error("secure_crypto::load_file_as_bytes: tellg failed");
        }
        size_t size = static_cast<size_t>(pos);
        file.seekg(0,ios::beg);

        //预分配缓冲区
        vector<uint8_t> buf(size);
        file.read(reinterpret_cast<char *>(buf.data()),size);

        if(!file) throw runtime_error("secure_crypto::load_file_as_bytes: file read fail"); 

        return buf;
    }

    void write_private_key_pem(const std::vector<uint8_t>& der_privkey, const std::string& filepath){
        BIO* bio=nullptr;
        EVP_PKEY* sk=nullptr;
        try{
            bio=BIO_new_file(filepath.data(),"w");
            if(!bio) throw runtime_error("secure_crypto::write_private_key_pem: BIO_new_file failed");
            //没法直接拿&取.data()后的值，所以得额外创立一个指针
            //将der格式的数据转换为pem格式数据,注意，私钥因为底层设计，是有必要检查底层类型的
            const unsigned char* p=der_privkey.data();
            d2i_PrivateKey(EVP_PKEY_NONE,&sk,&p,der_privkey.size());
            if(!sk)  throw runtime_error("secure_crypto::write_private_key_pem: d2i_PrivateKey fail");
            //写入文件
            if(PEM_write_bio_PrivateKey(bio,sk,NULL,NULL,0,NULL,NULL)!=1)
                throw runtime_error("secure_crypto::write_private_key_pem: PEM_write_bio_PrivateKey");
            BIO_free(bio);
            EVP_PKEY_free(sk);
        }catch(...){
            if(bio) BIO_free(bio);
            if(sk)  EVP_PKEY_free(sk);
            throw;
        }
    }

    
    void write_public_key_pem(const std::vector<uint8_t>& der_pubkey, const std::string& filepath){
        BIO* bio=nullptr;
        EVP_PKEY* pk=nullptr;
        try{
            bio=BIO_new_file(filepath.data(),"w");
            if(!bio) throw runtime_error("secure_crypto::write_public_key_pem: BIO_new_file failed");
            //没法直接拿&取.data()后的值，所以得额外创立一个指针
            //将der格式的数据转换为pem格式数据
            const unsigned char* p=der_pubkey.data();
            d2i_PUBKEY(&pk,&p,der_pubkey.size());
            if(!pk) throw runtime_error("secure_crypto::write_public_key_pem: d2i_PUBKEY fail");
            
            if(PEM_write_bio_PUBKEY(bio,pk)!=1)
                throw runtime_error("secure_crypto::write_public_key_pem: PEM_write_bio_PUBKEY");
            BIO_free(bio);
            EVP_PKEY_free(pk);
        }catch(...){
            if(bio) BIO_free(bio);
            if(pk)  EVP_PKEY_free(pk);
            throw;
        }
    }

    
    void write_bytes_to_file(const std::vector<uint8_t>& data, const std::string& filepath){
        ofstream file(filepath,ios::binary);
        if(!file) throw runtime_error("secure_crypto::write_bytes_to_file: file initiate fail");
        file.write(reinterpret_cast<const char*>(data.data()),data.size());
        if(!file) throw runtime_error("secure_crypto::write_bytes_to_file: file write fail");
    }
}