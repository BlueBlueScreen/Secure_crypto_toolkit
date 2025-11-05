#include<secure_crypto/secure_random.hpp>
#include<openssl/rand.h>
#include<stdexcept>
#include<limits>
using namespace std;
namespace secure_crypto{
    //检查输入是否合法
    vector<uint8_t> random_bytes(size_t n){
        if(n > static_cast<size_t>(numeric_limits<int>::max())){
            throw invalid_argument("secure_crypto::random_bytes: too many bytes");
        }
        //处理为0的特殊情况
        if(n==0){
            return vector<uint8_t>();
        }
        //分配缓冲区
        vector<uint8_t> buf(n);
        if(RAND_bytes(buf.data(),static_cast<int>(n))!=1)
            throw runtime_error("secure_crypto::random_bytes: OpenSSL RAND_bytes failed");
        return buf;
    }


    uint32_t rand_uint32(){
        uint32_t n;
        if(RAND_bytes(reinterpret_cast<unsigned char*>(&n),sizeof(n))!=1)
            throw runtime_error("secure_crypto::rand_uint32: OpenSSL RAND_bytes failed");
        return n;
    }

    uint64_t rand_uint64(){
        uint64_t n;
        if(RAND_bytes(reinterpret_cast<unsigned char*>(&n),sizeof(n))!=1)
            throw runtime_error("secure_crypto::rand_uint64: OpenSSL RAND_bytes failed");
        return n;
    }
    bool is_random_available()
    {
        return RAND_status()==1;
    }


}