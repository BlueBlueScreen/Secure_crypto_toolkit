#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "io.hpp"

namespace secure_crypto {

    // 生成 Ed25519 签名密钥对，以 PEM 格式写入文件
    void ed25519_keygen(const std::string& sk_path, const std::string& pk_path);

    // 用文件中的私钥对消息签名，返回 64 字节签名
    [[nodiscard]] std::vector<uint8_t> ed25519_sign(
        const std::string& sk_path,
        const std::vector<uint8_t>& message);

    // 用文件中的公钥验签；验签不通过返回 false（区别于文件读取失败等错误，后者抛异常）
    [[nodiscard]] bool ed25519_verify(
        const std::vector<uint8_t>& signature,
        const std::string& pk_path,
        const std::vector<uint8_t>& message);

}
