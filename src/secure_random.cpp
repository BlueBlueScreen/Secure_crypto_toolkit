#include <secure_crypto/secure_random.hpp>
#include <openssl/rand.h>
#include <stdexcept>
#include <limits>

namespace secure_crypto {

    std::vector<uint8_t> random_bytes(size_t n) {
        // RAND_bytes 的长度参数是 int，超限直接拒绝而不是截断
        if (n > static_cast<size_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument("secure_crypto::random_bytes: too many bytes");
        }
        if (n == 0) {
            return std::vector<uint8_t>();
        }
        std::vector<uint8_t> buf(n);
        // RAND_bytes 底层是 OpenSSL 的 CSPRNG（自动从系统熵源播种并定期 reseed）
        if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
            throw std::runtime_error("secure_crypto::random_bytes: OpenSSL RAND_bytes failed");
        return buf;
    }

    uint32_t rand_uint32() {
        uint32_t n;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&n), sizeof(n)) != 1)
            throw std::runtime_error("secure_crypto::rand_uint32: OpenSSL RAND_bytes failed");
        return n;
    }

    uint64_t rand_uint64() {
        uint64_t n;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&n), sizeof(n)) != 1)
            throw std::runtime_error("secure_crypto::rand_uint64: OpenSSL RAND_bytes failed");
        return n;
    }

    bool is_random_available() {
        // RAND_status()==1 表示 CSPRNG 已被足够熵播种
        return RAND_status() == 1;
    }

}
