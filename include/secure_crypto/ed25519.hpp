#include "io.hpp"
using namespace std;

namespace secure_crypto{
    //签名密钥对派生函数
    void sign_keygen(const string& sk_path,const string& pk_path);
    //签名函数
    vector<uint8_t> sign(const string& sk_path,const string& message);
    //验签函数
    bool verify(vector<uint8_t>& signature,const string& pk_path,const string& message);
}
