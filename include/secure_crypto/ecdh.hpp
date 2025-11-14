#include<iostream>
#include "io.hpp"

using namespace std;

namespace secure_crypto{
    //ecdh创建密钥对，生成密钥文件
    void ecdh_create_key(const string& sk_path,const string& pk_path);
    //ecdh根据本地私钥和远程公钥派生密钥
    vector<uint8_t> ecdh_derive_key(const string& sk_path,const string& pk_path);

}

