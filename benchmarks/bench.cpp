// 基础性能基准：AES-GCM 加解密吞吐 与 SHA-2/SHA-3 哈希吞吐
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <secure_crypto/aes_gcm.hpp>
#include <secure_crypto/secure_hash.hpp>
#include <secure_crypto/secure_random.hpp>

using namespace std::chrono;

// volatile sink：防止编译器把整个循环当死代码优化掉
static volatile size_t sink = 0;

static double mbs(size_t bytes, double total_iterations, const duration<double>& elapsed) {
    double total_bytes = static_cast<double>(bytes) * total_iterations;
    return (total_bytes / (1024.0 * 1024.0)) / elapsed.count();
}

static void bench_aes_gcm(size_t data_size, size_t iterations = 1000) {
    auto key = secure_crypto::random_bytes(32);
    auto aad = secure_crypto::random_bytes(16);
    auto plaintext = secure_crypto::random_bytes(data_size);

    // 预热，让 CPU 频率 / 缓存进入稳定状态
    for (size_t i = 0; i < 10; i++) {
        auto ct = secure_crypto::aes_gcm_encrypt(key, plaintext, aad);
        sink += secure_crypto::aes_gcm_decrypt(key, ct, aad).size();
    }

    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
        auto ct = secure_crypto::aes_gcm_encrypt(key, plaintext, aad);
        sink += secure_crypto::aes_gcm_decrypt(key, ct, aad).size();
    }
    auto elapsed = high_resolution_clock::now() - start;

    // 每轮加密 + 解密各处理 data_size 字节
    std::cout << "AES-256-GCM  size=" << std::setw(9) << data_size
              << " B  throughput(enc+dec)=" << std::fixed << std::setprecision(1)
              << mbs(data_size * 2, iterations, elapsed) << " MB/s\n";
}

template <typename HashFn>
static void bench_hash(const char* name, const std::vector<uint8_t>& data,
                       size_t iterations, HashFn fn) {
    for (size_t i = 0; i < 10; i++) sink += fn(data).size();

    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
        sink += fn(data).size();
    }
    auto elapsed = high_resolution_clock::now() - start;

    std::cout << name << "  size=" << std::setw(9) << data.size()
              << " B  throughput=" << std::fixed << std::setprecision(1)
              << mbs(data.size(), iterations, elapsed) << " MB/s\n";
}

int main() {
    std::cout << "--- AES-GCM (encrypt + decrypt) ---\n";
    for (size_t size : {size_t(64), size_t(1024), size_t(1024 * 1024)}) {
        bench_aes_gcm(size);
    }

    std::cout << "--- Hash ---\n";
    auto data = secure_crypto::random_bytes(1024 * 1024); // 1 MB
    bench_hash("SHA-256  ", data, 500, [](const std::vector<uint8_t>& d) {
        return secure_crypto::sha256(d);
    });
    bench_hash("SHA-512  ", data, 500, [](const std::vector<uint8_t>& d) {
        return secure_crypto::sha512(d);
    });
    bench_hash("SHA3-256 ", data, 500, [](const std::vector<uint8_t>& d) {
        return secure_crypto::sha3_256(d);
    });
    bench_hash("SHA3-512 ", data, 500, [](const std::vector<uint8_t>& d) {
        return secure_crypto::sha3_512(d);
    });
    return 0;
}
