#include <secure_crypto/io.hpp>
#include <fstream>
#include <stdexcept>

namespace secure_crypto {

    // 本库只支持这两种现代算法。加载/写出密钥时统一检查，
    // RSA、DSA、prime256v1 之类的遗留密钥即使在文件里也会被拒绝
    static bool is_supported_key_id(int id) {
        return id == EVP_PKEY_X25519 || id == EVP_PKEY_ED25519;
    }

    std::vector<uint8_t> load_private_key_der_from_pem(const std::string& filepath) {
        BIO* bio = nullptr;
        EVP_PKEY* sk = nullptr;
        BIO* mem_bio = nullptr;
        try {
            // 只读模式打开文件
            bio = BIO_new_file(filepath.c_str(), "r");
            if (!bio)
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: cannot open file");
            // 尝试读取私钥；文件是公钥或格式不对则失败
            sk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            if (!sk)
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: not a valid private key PEM");
            // 检查密钥算法是否在白名单内
            if (!is_supported_key_id(EVP_PKEY_get_id(sk)))
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: unsupported key algorithm");
            // 序列化成 DER 字节输出
            mem_bio = BIO_new(BIO_s_mem());
            if (!mem_bio)
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: BIO_new failed");
            if (i2d_PrivateKey_bio(mem_bio, sk) != 1)
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: i2d_PrivateKey_bio failed");
            // 从内存 BIO 中提取字节
            char* data = nullptr;
            long len = BIO_get_mem_data(mem_bio, &data);
            if (len <= 0 || !data)
                throw std::runtime_error("secure_crypto::load_private_key_der_from_pem: BIO_get_mem_data failed");

            std::vector<uint8_t> der(data, data + len);
            BIO_free(mem_bio);
            BIO_free(bio);
            EVP_PKEY_free(sk);
            return der;
        } catch (...) {
            if (mem_bio) BIO_free(mem_bio);
            if (bio) BIO_free(bio);
            if (sk) EVP_PKEY_free(sk);
            throw;
        }
    }

    std::vector<uint8_t> load_public_key_der_from_pem(const std::string& filepath) {
        BIO* bio = nullptr;
        EVP_PKEY* pk = nullptr;
        BIO* mem_bio = nullptr;
        try {
            bio = BIO_new_file(filepath.c_str(), "r");
            if (!bio)
                throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: cannot open file");
            // 先尝试按公钥读取
            pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            if (!pk) {
                // 读不到公钥就回退读私钥——私钥文件里也包含公钥部分
                BIO_reset(bio);
                pk = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
                if (!pk)
                    throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: cannot read key");
            }
            // 同样检查密钥算法白名单
            if (!is_supported_key_id(EVP_PKEY_get_id(pk)))
                throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: unsupported key algorithm");
            // 序列化成 SubjectPublicKeyInfo 格式的 DER
            mem_bio = BIO_new(BIO_s_mem());
            if (!mem_bio)
                throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: BIO_new failed");
            if (i2d_PUBKEY_bio(mem_bio, pk) != 1)
                throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: i2d_PUBKEY_bio failed");
            char* data = nullptr;
            long len = BIO_get_mem_data(mem_bio, &data);
            if (len <= 0 || !data)
                throw std::runtime_error("secure_crypto::load_public_key_der_from_pem: BIO_get_mem_data failed");

            std::vector<uint8_t> der(data, data + len);
            BIO_free(mem_bio);
            BIO_free(bio);
            EVP_PKEY_free(pk);
            return der;
        } catch (...) {
            if (mem_bio) BIO_free(mem_bio);
            if (bio) BIO_free(bio);
            if (pk) EVP_PKEY_free(pk);
            throw;
        }
    }

    std::vector<uint8_t> load_file_as_bytes(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file)
            throw std::runtime_error("secure_crypto::load_file_as_bytes: cannot open file");

        // 用文件末尾位置算出大小
        file.seekg(0, std::ios::end);
        std::streampos pos = file.tellg();
        if (pos < 0) {
            throw std::runtime_error("secure_crypto::load_file_as_bytes: tellg failed");
        }
        size_t size = static_cast<size_t>(pos);
        file.seekg(0, std::ios::beg);

        // 预分配缓冲区一次性读入
        std::vector<uint8_t> buf(size);
        if (size > 0) {
            file.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
            if (!file)
                throw std::runtime_error("secure_crypto::load_file_as_bytes: read failed");
        }
        return buf;
    }

    void write_private_key_pem(const std::vector<uint8_t>& der_privkey, const std::string& filepath) {
        BIO* bio = nullptr;
        EVP_PKEY* sk = nullptr;
        try {
            // DER -> EVP_PKEY，指定期望类型为 X25519/Ed25519 之外的通用解码后再查白名单
            const unsigned char* p = der_privkey.data();
            sk = d2i_AutoPrivateKey(&sk, &p, static_cast<long>(der_privkey.size()));
            if (!sk)
                throw std::runtime_error("secure_crypto::write_private_key_pem: d2i_AutoPrivateKey failed");
            if (!is_supported_key_id(EVP_PKEY_get_id(sk)))
                throw std::runtime_error("secure_crypto::write_private_key_pem: unsupported key algorithm");

            bio = BIO_new_file(filepath.c_str(), "w");
            if (!bio)
                throw std::runtime_error("secure_crypto::write_private_key_pem: cannot open file");
            // 后四个加密参数传 NULL/0 表示不加密写出（密钥文件权限由部署环境保证）
            if (PEM_write_bio_PrivateKey(bio, sk, NULL, NULL, 0, NULL, NULL) != 1)
                throw std::runtime_error("secure_crypto::write_private_key_pem: PEM_write failed");
            BIO_free(bio);
            EVP_PKEY_free(sk);
        } catch (...) {
            if (bio) BIO_free(bio);
            if (sk) EVP_PKEY_free(sk);
            throw;
        }
    }

    void write_public_key_pem(const std::vector<uint8_t>& der_pubkey, const std::string& filepath) {
        BIO* bio = nullptr;
        EVP_PKEY* pk = nullptr;
        try {
            const unsigned char* p = der_pubkey.data();
            pk = d2i_PUBKEY(NULL, &p, static_cast<long>(der_pubkey.size()));
            if (!pk)
                throw std::runtime_error("secure_crypto::write_public_key_pem: d2i_PUBKEY failed");
            if (!is_supported_key_id(EVP_PKEY_get_id(pk)))
                throw std::runtime_error("secure_crypto::write_public_key_pem: unsupported key algorithm");

            bio = BIO_new_file(filepath.c_str(), "w");
            if (!bio)
                throw std::runtime_error("secure_crypto::write_public_key_pem: cannot open file");
            if (PEM_write_bio_PUBKEY(bio, pk) != 1)
                throw std::runtime_error("secure_crypto::write_public_key_pem: PEM_write failed");
            BIO_free(bio);
            EVP_PKEY_free(pk);
        } catch (...) {
            if (bio) BIO_free(bio);
            if (pk) EVP_PKEY_free(pk);
            throw;
        }
    }

    void write_private_key(EVP_PKEY* pkey, const std::string& filepath) {
        BIO* bio = nullptr;
        try {
            if (!pkey)
                throw std::runtime_error("secure_crypto::write_private_key: null pkey");
            if (!is_supported_key_id(EVP_PKEY_get_id(pkey)))
                throw std::runtime_error("secure_crypto::write_private_key: unsupported key algorithm");

            bio = BIO_new_file(filepath.c_str(), "w");
            if (!bio)
                throw std::runtime_error("secure_crypto::write_private_key: cannot open file");
            if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1)
                throw std::runtime_error("secure_crypto::write_private_key: PEM_write failed");
            BIO_free(bio);
        } catch (...) {
            if (bio) BIO_free(bio);
            throw;
        }
    }

    void write_public_key(EVP_PKEY* pkey, const std::string& filepath) {
        BIO* bio = nullptr;
        try {
            if (!pkey)
                throw std::runtime_error("secure_crypto::write_public_key: null pkey");
            if (!is_supported_key_id(EVP_PKEY_get_id(pkey)))
                throw std::runtime_error("secure_crypto::write_public_key: unsupported key algorithm");

            bio = BIO_new_file(filepath.c_str(), "w");
            if (!bio)
                throw std::runtime_error("secure_crypto::write_public_key: cannot open file");
            if (PEM_write_bio_PUBKEY(bio, pkey) != 1)
                throw std::runtime_error("secure_crypto::write_public_key: PEM_write failed");
            BIO_free(bio);
        } catch (...) {
            if (bio) BIO_free(bio);
            throw;
        }
    }

    void write_bytes_to_file(const std::vector<uint8_t>& data, const std::string& filepath) {
        std::ofstream file(filepath, std::ios::binary);
        if (!file)
            throw std::runtime_error("secure_crypto::write_bytes_to_file: cannot open file");
        if (!data.empty()) {
            file.write(reinterpret_cast<const char*>(data.data()),
                       static_cast<std::streamsize>(data.size()));
            if (!file)
                throw std::runtime_error("secure_crypto::write_bytes_to_file: write failed");
        }
    }

}
