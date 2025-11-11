#include<secure_crypto/utils.hpp>
#include<stdexcept>
using namespace std;

namespace secure_crypto{
    string base64_encode(const vector<uint8_t>& data){
        //定义返回变量
        string res="";
        if(data.empty()) return res;
        //base64编码按3字节（24位）进行分组，因此我们首先输入字节串长度是否未3的倍数，不够就补齐
        vector<uint8_t> bitstring=data;
        size_t padding_len=0;
        switch(data.size()%3){
            case 0: padding_len=0;
                    break;
            case 1: padding_len=2;
                    break;
            case 2: padding_len=1;
        }
        for(size_t i=0;i<padding_len;i++){
            bitstring.push_back(static_cast<uint8_t>(0));
        }
        //分完组后，按照base64的编码规则，一次取出三个字节，然后再分成四组
        for(size_t i=0;i<bitstring.size();i+=3){
            uint8_t b0=bitstring[i];
            uint8_t b1=bitstring[i+1];
            uint8_t b2=bitstring[i+2];
            int index0,index1,index2,index3;
            index0=(b0>>2)&0x3F;
            index1=((b0&0x03)<<4)|(b1>>4);
            index2=((b1&0x0F)<<2)|(b2>>6);
            index3=b2&0x3F;
            res+=base64_alphabet[index0];
            res+=base64_alphabet[index1];
            res+=base64_alphabet[index2];
            res+=base64_alphabet[index3];
        }
        //替换末尾因0产生的无效字符，base64的设计保证了这个替换不改变原意
        for (size_t i = 0; i < padding_len; ++i) {
            res[res.size() - 1 - i] = '=';
}
        return res;
    }
    vector<uint8_t> base64_decode(const string& data){
        vector<uint8_t> res;
        //首先检查是否为空串
        if(data.empty()) return {};
        //检查是否为合法长度
        if (data.size() % 4 != 0) {
        throw std::runtime_error("Invalid Base64 length");
    }
        //进行预分配
        res.reserve(data.size()*3/4);
        //然后检查所有的字符是否都符合要求，如果不符合则报错
        for(char c:data){
            if(base64_alphabet.find(c)==string::npos&&c!='='){
                throw runtime_error("secure_crypto::base64_decode: Input format wrong");
            } 
        }
        //检查填充字符数
        size_t padding_len=0;
        for(auto it=data.rbegin();it!=data.rend();it++){
            if(*it=='=') padding_len++;
            else break;
        }
        if(padding_len>=3) throw runtime_error("secure_crypto::base64_decode: Input format wrong");
        //此时还需要补充对'='的检查，毕竟先前的是没检查上的
        for (size_t i = 0; i < data.size() - padding_len; ++i) {
            if (data[i] == '=') {
                throw std::runtime_error("secure_crypto::base64_decode:Invalid '=' in non-padding position");
            }
        }

        //进行解密
        for(size_t i=0;i<data.size();i+=4){
            int i0= base64_inverse_table[(static_cast<unsigned char>(data[i]))];
            int i1= base64_inverse_table[(static_cast<unsigned char>(data[i+1]))];
            int i2= base64_inverse_table[(static_cast<unsigned char>(data[i+2]))];
            int i3= base64_inverse_table[(static_cast<unsigned char>(data[i+3]))];
        //需要额外处理末尾可能的'='
            if(data[i+2]=='=') i2=0;
            if(data[i+3]=='=') i3=0;
            uint8_t b0,b1,b2;
            b0 = (i0 << 2) | (i1 >> 4);
            b1 = ((i1 & 0x0F) << 4) | (i2 >> 2);
            b2 = ((i2 & 0x03) << 6) | i3;
            res.push_back(b0);
            res.push_back(b1);
            res.push_back(b2);
        }
        res.resize(res.size()-padding_len);
        return res;
    }

    bool const_time_compare(const vector<uint8_t>& a,const vector<uint8_t>& b){
        uint8_t res=0;
        if(a.size()!=b.size()) return false;
        int len=a.size();
        for(int i=0;i<len;i++){
            res|=a[i]^b[i];
        }
        return res==0;
    }

    string hex_encode(const vector<uint8_t>& data){
        if(data.size()==0) return "";
        string res(2*data.size(),'0');
        int len=data.size();
        for(int i=0;i<len;i++){
            res[2*i]=hex_chars[data[i]>>4];
            res[2*i+1]=hex_chars[data[i]&0x0F];
        }
        return res;
    }
    vector<uint8_t> hex_decode(const std::string& hex){
        if(hex.empty()) return {};

        //长度一定是2的倍数
        if(hex.size()%2!=0) throw runtime_error("secure_crypto::hex_decode: Input length error");
        vector<uint8_t> res(hex.size()/2,0);
        size_t len=hex.size();
        for(size_t i=0;i<len;i+=2){
            int hi=hex_inverse_table[(static_cast<unsigned char>(hex[i]))];
            int oi=hex_inverse_table[(static_cast<unsigned char>(hex[i+1]))];
            if(hi==-1||oi==-1)
                throw runtime_error("secure_crypto::hex_decode: Input type error");
            res[i/2]=(static_cast<uint8_t>(hi<<4)|oi);
        }
        return res;
    }

}