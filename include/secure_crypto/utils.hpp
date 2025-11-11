#include<iostream>
#include<cstddef>
#include<cstdint>
#include<vector>
#include<array>
using namespace std;

namespace secure_crypto{
    //进行base64转换所需的预设字符转换表
    constexpr std::string_view base64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

    //解码base64所需的反查表，最高效的方式为ASCII码值向base64预设表符号的映射
constexpr array<int, 256> make_base64_inverse_table() {
    array<int, 256> table{};
    // 不能用 fill，手动初始化为 -1
    for (int i = 0; i < 256; ++i) {
        table[i] = -1;
    }
    constexpr char alphabet[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(alphabet[i])] = i;
    }
    return table;
}
// 预计算 256 字节查找表（类似 Base64）
constexpr array<int, 256> make_hex_inverse_table() {
    std::array<int, 256> table{};
    for (int i = 0; i < 256; ++i) {
        table[i] = -1;
    }
    for (int i = 0; i < 10; ++i) table['0' + i] = i;
    for (int i = 0; i < 6; ++i) {
        table['a' + i] = table['A' + i] = 10 + i;
    }
    return table;
}
constexpr auto hex_inverse_table = make_hex_inverse_table();

constexpr auto base64_inverse_table = make_base64_inverse_table();
constexpr string_view hex_chars = "0123456789abcdef";

    //base64编解码
    string base64_encode(const vector<uint8_t>& data);
    vector<uint8_t> base64_decode(const string& data);
    //恒定时间比较函数
    bool const_time_compare(const vector<uint8_t>& a,const vector<uint8_t>& b);
    //十六进制编解码
    string hex_encode(const vector<uint8_t>& data);
    vector<uint8_t> hex_decode(const std::string& hex);

}