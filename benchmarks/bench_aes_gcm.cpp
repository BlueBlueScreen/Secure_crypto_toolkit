#include<iostream>
#include<vector>
#include<chrono>
#include<iomanip>
#include<secure_crypto/aes_gcm.hpp>
#include<secure_crypto/secure_random.hpp>
using namespace std;
using namespace std::chrono;

void bench_aes_gcm(size_t data_size, size_t iterations = 1000) {
    auto key = secure_crypto::random_bytes(32);
    auto aad = secure_crypto::random_bytes(16);
    auto plaintext= secure_crypto::random_bytes(data_size);
    // 直接使用 vector，避免 string 截断
    std::string ptext(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

    // 预热
    for (int i = 0; i < 10; ++i) {
        auto cipher_tuple = secure_crypto::aes_gcm_encrypt(key, ptext, aad);
        secure_crypto::aes_gcm_decrypt(key, cipher_tuple, aad);
    }

    volatile size_t sink = 0; // 防优化
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        auto cipher_tuple = secure_crypto::aes_gcm_encrypt(key, ptext, aad);
        auto decrypted = secure_crypto::aes_gcm_decrypt(key, cipher_tuple, aad);
        sink += decrypted.size();
    }
    auto end = high_resolution_clock::now();

    auto total_ns = duration_cast<nanoseconds>(end - start).count();
    double total_bytes = static_cast<double>(data_size) * iterations * 2; // 加密+解密
    double throughput_mbs = (total_bytes / (1024.0 * 1024.0)) / (total_ns / 1e9);

    std::cout << "Data size: " << std::setw(8) << data_size << " B, "
              << "Throughput: " << std::fixed << std::setprecision(2) << throughput_mbs << " MB/s\n";
}

int main() {
    std::vector<size_t> sizes = {64, 1024, 1024*1024}; // 64B, 1KB, 1MB
    for (auto size : sizes) {
        bench_aes_gcm(size);
    }
    return 0;
}