#pragma once
#include <openssl/evp.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// 本头文件只提供 SHA-2（FIPS 180-4）与 SHA-3（FIPS 202）家族。
// 有意不提供 MD5 / SHA-1 接口：二者已不具备抗碰撞性，属于"弱算法"，
// 从接口层面禁用，调用方无法误用。

namespace secure_crypto {
namespace detail {

    // 分段更新哈希上下文，支持字节串和 std::string 两种输入
    inline void hash_update(EVP_MD_CTX* ctx, const std::vector<uint8_t>& data) {
        if (!data.empty() && EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
            throw std::runtime_error("secure_crypto::hash_update: Update failed");
    }

    inline void hash_update(EVP_MD_CTX* ctx, const std::string& s) {
        if (!s.empty() && EVP_DigestUpdate(ctx, s.data(), s.size()) != 1)
            throw std::runtime_error("secure_crypto::hash_update: Update failed");
    }

    // 一次性哈希（调用方传字节串）
    inline std::vector<uint8_t> hash_once(const EVP_MD* md, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> buf(EVP_MD_size(md));
        unsigned int len = 0;
        if (EVP_Digest(data.data(), data.size(), buf.data(), &len, md, NULL) != 1)
            throw std::runtime_error("secure_crypto::hash_once: EVP_Digest failed");
        buf.resize(len);
        return buf;
    }

    // 通用"多段拼接后哈希"模板：所有算法共用这一份实现，只是传入不同的 EVP_MD
    // 例如 sha256_concat("part1", bytes, "part2")
    template <typename... Args>
    [[nodiscard]] inline std::vector<uint8_t> hash_concat(const EVP_MD* md, const Args&... args) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("secure_crypto::hash_concat: EVP_MD_CTX_new failed");
        std::vector<uint8_t> digest(EVP_MD_size(md));
        unsigned int len = 0;
        try {
            if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
                throw std::runtime_error("secure_crypto::hash_concat: Init error");
            // C++17 折叠表达式，把每个参数依次喂给 hash_update
            (hash_update(ctx, args), ...);
            if (EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1)
                throw std::runtime_error("secure_crypto::hash_concat: DigestFinal error");
            digest.resize(len);
            EVP_MD_CTX_free(ctx);
            return digest;
        } catch (...) {
            EVP_MD_CTX_free(ctx);
            throw;
        }
    }

} // namespace detail

// ---------- SHA-2 家族 ----------
[[nodiscard]] inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha256(), data);
}
[[nodiscard]] inline std::vector<uint8_t> sha384(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha384(), data);
}
[[nodiscard]] inline std::vector<uint8_t> sha512(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha512(), data);
}

template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha256_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha256(), args...);
}
template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha384_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha384(), args...);
}
template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha512_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha512(), args...);
}

// ---------- SHA-3 家族 ----------
[[nodiscard]] inline std::vector<uint8_t> sha3_256(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha3_256(), data);
}
[[nodiscard]] inline std::vector<uint8_t> sha3_384(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha3_384(), data);
}
[[nodiscard]] inline std::vector<uint8_t> sha3_512(const std::vector<uint8_t>& data) {
    return detail::hash_once(EVP_sha3_512(), data);
}

template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha3_256_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha3_256(), args...);
}
template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha3_384_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha3_384(), args...);
}
template <typename... Args>
[[nodiscard]] std::vector<uint8_t> sha3_512_concat(const Args&... args) {
    return detail::hash_concat(EVP_sha3_512(), args...);
}

}
