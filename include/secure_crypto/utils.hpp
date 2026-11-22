#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <string_view>

namespace secure_crypto {

    // base64 编码字符表（RFC 4648 标准表）
    constexpr std::string_view base64_alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    // 解码用的反查表：ASCII 码值 -> 6bit 序号，非法字符为 -1
    // 用 constexpr 函数在编译期把表算好，运行期零开销
    constexpr std::array<int, 256> make_base64_inverse_table() {
        std::array<int, 256> table{};
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

    constexpr std::array<int, 256> make_hex_inverse_table() {
        std::array<int, 256> table{};
        for (int i = 0; i < 256; ++i) {
            table[i] = -1;
        }
        for (int i = 0; i < 10; ++i) table['0' + i] = i;
        for (int i = 0; i < 6; ++i) {
            table['a' + i] = table['A' + i] = 10 + i; // 大小写十六进制都接受
        }
        return table;
    }

    constexpr auto hex_inverse_table = make_hex_inverse_table();
    constexpr auto base64_inverse_table = make_base64_inverse_table();
    constexpr std::string_view hex_chars = "0123456789abcdef";

    // base64 编解码
    [[nodiscard]] std::string base64_encode(const std::vector<uint8_t>& data);
    [[nodiscard]] std::vector<uint8_t> base64_decode(const std::string& data);
    // 恒定时间比较：逐字节全量比较，不提前退出，防止用比较耗时猜测密钥（timing side-channel）
    [[nodiscard]] bool const_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    // 十六进制编解码
    [[nodiscard]] std::string hex_encode(const std::vector<uint8_t>& data);
    [[nodiscard]] std::vector<uint8_t> hex_decode(const std::string& hex);

}
