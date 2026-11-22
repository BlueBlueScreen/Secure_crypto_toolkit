#include <secure_crypto/utils.hpp>
#include <stdexcept>

namespace secure_crypto {

    std::string base64_encode(const std::vector<uint8_t>& data) {
        std::string res;
        if (data.empty()) return res;

        // base64 按 3 字节（24 位）一组编码，末尾不足 3 字节先补 0，
        // 编码完成后再把补位对应的位置替换成 '='
        std::vector<uint8_t> bitstring = data;
        size_t padding_len = 0;
        switch (data.size() % 3) {
            case 0: padding_len = 0; break;
            case 1: padding_len = 2; break;
            case 2: padding_len = 1; break;
        }
        for (size_t i = 0; i < padding_len; i++) {
            bitstring.push_back(static_cast<uint8_t>(0));
        }

        // 每 3 字节拆成 4 个 6bit 序号，查字符表输出
        for (size_t i = 0; i < bitstring.size(); i += 3) {
            uint8_t b0 = bitstring[i];
            uint8_t b1 = bitstring[i + 1];
            uint8_t b2 = bitstring[i + 2];
            int index0 = (b0 >> 2) & 0x3F;
            int index1 = ((b0 & 0x03) << 4) | (b1 >> 4);
            int index2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
            int index3 = b2 & 0x3F;
            res += base64_alphabet[index0];
            res += base64_alphabet[index1];
            res += base64_alphabet[index2];
            res += base64_alphabet[index3];
        }
        // 末尾补位产生的字符是无效的，替换为 '='（RFC 4648 规则）
        for (size_t i = 0; i < padding_len; ++i) {
            res[res.size() - 1 - i] = '=';
        }
        return res;
    }

    std::vector<uint8_t> base64_decode(const std::string& data) {
        if (data.empty()) return {};
        // 合法 base64 长度必为 4 的倍数
        if (data.size() % 4 != 0) {
            throw std::runtime_error("secure_crypto::base64_decode: invalid length");
        }
        std::vector<uint8_t> res;
        res.reserve(data.size() / 4 * 3);

        // 字符集检查
        for (char c : data) {
            if (base64_alphabet.find(c) == std::string_view::npos && c != '=') {
                throw std::runtime_error("secure_crypto::base64_decode: invalid character");
            }
        }
        // 统计末尾填充 '=' 的个数，最多 2 个
        size_t padding_len = 0;
        for (auto it = data.rbegin(); it != data.rend(); it++) {
            if (*it == '=') padding_len++;
            else break;
        }
        if (padding_len >= 3)
            throw std::runtime_error("secure_crypto::base64_decode: too much padding");
        // '=' 只允许出现在末尾，前面的位置不能出现
        for (size_t i = 0; i < data.size() - padding_len; ++i) {
            if (data[i] == '=') {
                throw std::runtime_error("secure_crypto::base64_decode: '=' in non-padding position");
            }
        }

        // 每 4 个字符还原 3 字节
        for (size_t i = 0; i < data.size(); i += 4) {
            int i0 = base64_inverse_table[static_cast<unsigned char>(data[i])];
            int i1 = base64_inverse_table[static_cast<unsigned char>(data[i + 1])];
            int i2 = base64_inverse_table[static_cast<unsigned char>(data[i + 2])];
            int i3 = base64_inverse_table[static_cast<unsigned char>(data[i + 3])];
            // 末尾 '=' 位置查表得 -1，按 0 参与运算，最后统一裁掉
            if (data[i + 2] == '=') i2 = 0;
            if (data[i + 3] == '=') i3 = 0;
            uint8_t b0 = static_cast<uint8_t>((i0 << 2) | (i1 >> 4));
            uint8_t b1 = static_cast<uint8_t>(((i1 & 0x0F) << 4) | (i2 >> 2));
            uint8_t b2 = static_cast<uint8_t>(((i2 & 0x03) << 6) | i3);
            res.push_back(b0);
            res.push_back(b1);
            res.push_back(b2);
        }
        res.resize(res.size() - padding_len);
        return res;
    }

    bool const_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        // 把所有字节的差异累积到一个变量上，循环完整走完才返回，
        // 比较耗时不随"第几个字节开始不同"变化，抵抗计时侧信道
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    std::string hex_encode(const std::vector<uint8_t>& data) {
        if (data.empty()) return "";
        std::string res(2 * data.size(), '0');
        for (size_t i = 0; i < data.size(); i++) {
            res[2 * i] = hex_chars[data[i] >> 4];
            res[2 * i + 1] = hex_chars[data[i] & 0x0F];
        }
        return res;
    }

    std::vector<uint8_t> hex_decode(const std::string& hex) {
        if (hex.empty()) return {};
        // 长度必为 2 的倍数
        if (hex.size() % 2 != 0)
            throw std::runtime_error("secure_crypto::hex_decode: odd input length");
        std::vector<uint8_t> res(hex.size() / 2, 0);
        for (size_t i = 0; i < hex.size(); i += 2) {
            int hi = hex_inverse_table[static_cast<unsigned char>(hex[i])];
            int oi = hex_inverse_table[static_cast<unsigned char>(hex[i + 1])];
            if (hi == -1 || oi == -1)
                throw std::runtime_error("secure_crypto::hex_decode: invalid character");
            res[i / 2] = static_cast<uint8_t>((hi << 4) | oi);
        }
        return res;
    }

}
