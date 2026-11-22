#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>

namespace secure_crypto {

// 生成 n 字节密码学安全随机数（基于 OpenSSL RAND_bytes，CSPRNG）
[[nodiscard]] std::vector<uint8_t> random_bytes(size_t n);
// 生成 32bit 随机数
[[nodiscard]] uint32_t rand_uint32();
// 生成 64bit 随机数
[[nodiscard]] uint64_t rand_uint64();
// 检查随机数生成器是否已正确播种
[[nodiscard]] bool is_random_available();

}
