#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "io.hpp"

namespace secure_crypto {

    // 生成 X25519（Curve25519 上的 ECDH）密钥对，以 PEM 格式分别写入两个文件
    void x25519_keygen(const std::string& sk_path, const std::string& pk_path);

    // 本地私钥 + 对方公钥 -> 32 字节原始共享密钥。
    // 注意：输出是 ECDH 的裸共享秘密，分布不完全均匀，
    // 实际协议中应再经 HKDF 派生成会话密钥
    [[nodiscard]] std::vector<uint8_t> x25519_derive(
        const std::string& local_sk_path,
        const std::string& peer_pk_path);

}
