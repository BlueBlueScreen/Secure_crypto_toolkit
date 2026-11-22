#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>

namespace secure_crypto {

// HKDF-SHA256（RFC 5869，EXTRACT_AND_EXPAND 模式）
// 用途：把 X25519 协商出的原始共享密钥等"非均匀"密钥材料派生成均匀随机密钥
[[nodiscard]] std::vector<uint8_t> hkdf_sha256(
    const std::vector<uint8_t>& ikm,  // 输入密钥材料
    size_t n,                         // 输出长度
    const std::vector<uint8_t>& salt = {},
    const std::vector<uint8_t>& info = {}
);

}
