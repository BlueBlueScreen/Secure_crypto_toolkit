#include <stdexcept>
#include <secure_crypto/x25519.hpp>

namespace secure_crypto {

    void x25519_keygen(const std::string& sk_path, const std::string& pk_path) {
        // 在 EVP_PKEY_CTX 里指定密钥类型，keygen 时就会使用 X25519 曲线
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (!ctx)
            throw std::runtime_error("secure_crypto::x25519_keygen: EVP_PKEY_CTX_new_id failed");

        EVP_PKEY* pkey = nullptr;
        try {
            if (EVP_PKEY_keygen_init(ctx) != 1)
                throw std::runtime_error("secure_crypto::x25519_keygen: EVP_PKEY_keygen_init failed");
            if (EVP_PKEY_keygen(ctx, &pkey) != 1)
                throw std::runtime_error("secure_crypto::x25519_keygen: EVP_PKEY_keygen failed");

            // 私钥、公钥分别写入 PEM 文件
            write_private_key(pkey, sk_path);
            write_public_key(pkey, pk_path);

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
        } catch (...) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw;
        }
    }

    std::vector<uint8_t> x25519_derive(
        const std::string& local_sk_path,
        const std::string& peer_pk_path)
    {
        // 先读本地私钥和对方公钥（均为 DER 字节，io 层已校验密钥算法白名单）
        std::vector<uint8_t> sk_der = load_private_key_der_from_pem(local_sk_path);
        std::vector<uint8_t> pk_der = load_public_key_der_from_pem(peer_pk_path);

        // 反序列化为 EVP_PKEY 对象
        const unsigned char* p_sk = sk_der.data();
        const unsigned char* p_pk = pk_der.data();
        EVP_PKEY* sk = nullptr;
        EVP_PKEY* pk = nullptr;
        EVP_PKEY_CTX* ctx = nullptr;
        try {
            sk = d2i_PrivateKey_ex(EVP_PKEY_X25519, NULL, &p_sk,
                                   static_cast<long>(sk_der.size()), NULL, NULL);
            if (!sk)
                throw std::runtime_error("secure_crypto::x25519_derive: decode private key failed");
            pk = d2i_PUBKEY(NULL, &p_pk, static_cast<long>(pk_der.size()));
            if (!pk)
                throw std::runtime_error("secure_crypto::x25519_derive: decode public key failed");

            ctx = EVP_PKEY_CTX_new(sk, NULL);
            if (!ctx)
                throw std::runtime_error("secure_crypto::x25519_derive: EVP_PKEY_CTX_new failed");
            if (EVP_PKEY_derive_init(ctx) != 1)
                throw std::runtime_error("secure_crypto::x25519_derive: derive_init failed");
            if (EVP_PKEY_derive_set_peer(ctx, pk) != 1)
                throw std::runtime_error("secure_crypto::x25519_derive: derive_set_peer failed");

            // 惯用法：第一次传 NULL 只查询长度，第二次真正派生
            size_t keylen = 0;
            if (EVP_PKEY_derive(ctx, NULL, &keylen) != 1)
                throw std::runtime_error("secure_crypto::x25519_derive: query key length failed");
            std::vector<uint8_t> shared_secret(keylen);
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &keylen) != 1)
                throw std::runtime_error("secure_crypto::x25519_derive: derive failed");
            shared_secret.resize(keylen);

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pk);
            EVP_PKEY_free(sk);
            return shared_secret;
        } catch (...) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pk);
            EVP_PKEY_free(sk);
            throw;
        }
    }

}
