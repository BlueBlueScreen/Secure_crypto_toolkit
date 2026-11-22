#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace secure_crypto {

// AES-GCM 的加密结果。用带名字的 struct 而不是 tuple，
// 调用方不可能把密文 / 认证标签 / nonce 搞混
struct GcmCiphertext {
    std::vector<uint8_t> ciphertext; // 密文（与明文等长）
    std::vector<uint8_t> tag;        // 16 字节认证标签
    std::vector<uint8_t> nonce;      // 12 字节随机 nonce，每次加密重新生成
};

// 仅接受 16 或 32 字节密钥（AES-128/256-GCM），不提供其他长度
// nonce 由库内部用 CSPRNG 生成，防止调用方误用固定 nonce（GCM 下 nonce 重用即灾难）
[[nodiscard]] GcmCiphertext aes_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad = {} // 可选附加认证数据（只认证、不加密）
);

// 认证标签或 AAD 校验失败时抛出 std::runtime_error
[[nodiscard]] std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const GcmCiphertext& ct,
    const std::vector<uint8_t>& aad = {}
);

}
