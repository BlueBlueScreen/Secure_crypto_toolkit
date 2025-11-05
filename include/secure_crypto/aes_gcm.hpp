#include<cstdint>
#include<cstddef>
#include<openssl/evp.h>
#include<vector>
#include<string>
#include<stdexcept>
#include<tuple>
#include "./secure_random.hpp"
using namespace std;

namespace secure_crypto{
    tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> aes_gcm_encrypt(
        const vector<uint8_t>& key, //密钥设置为可以选做128位或者256位
        const string& plaintext,  //传入string类型明文后续进行转换
        const vector<uint8_t>& aad //可选附加数据
    );

    //解密输出结果为sting类型明文
    string aes_gcm_decrypt(
        const vector<uint8_t>& key,
        tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple,
        const vector<uint8_t>& aad
    );

}