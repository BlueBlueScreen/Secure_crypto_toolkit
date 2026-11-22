#include <stdexcept>
#include <secure_crypto/ed25519.hpp>

namespace secure_crypto {

    void ed25519_keygen(const std::string& sk_path, const std::string& pk_path) {
        // 通过密钥类型指定使用 Ed25519 曲线
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!ctx)
            throw std::runtime_error("secure_crypto::ed25519_keygen: EVP_PKEY_CTX_new_id failed");

        EVP_PKEY* pkey = nullptr;
        try {
            if (EVP_PKEY_keygen_init(ctx) != 1)
                throw std::runtime_error("secure_crypto::ed25519_keygen: keygen_init failed");
            if (EVP_PKEY_keygen(ctx, &pkey) != 1)
                throw std::runtime_error("secure_crypto::ed25519_keygen: keygen failed");

            // 保存公私钥
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

    std::vector<uint8_t> ed25519_sign(
        const std::string& sk_path,
        const std::vector<uint8_t>& message)
    {
        // 读取私钥（DER 字节）
        std::vector<uint8_t> sk_der = load_private_key_der_from_pem(sk_path);

        EVP_PKEY* sk = nullptr;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("secure_crypto::ed25519_sign: EVP_MD_CTX_new failed");

        try {
            const unsigned char* p = sk_der.data();
            sk = d2i_PrivateKey_ex(EVP_PKEY_ED25519, NULL, &p,
                                   static_cast<long>(sk_der.size()), NULL, NULL);
            if (!sk)
                throw std::runtime_error("secure_crypto::ed25519_sign: decode private key failed");

            // Ed25519 是纯签名方案：无 hash、无盐，所以 EVP_DigestSignInit 的 md/engine 都传 NULL
            if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, sk) != 1)
                throw std::runtime_error("secure_crypto::ed25519_sign: EVP_DigestSignInit failed");

            // 与 ECDH 派生类似的两次调用：先查签名长度，再真正签名
            size_t siglen = 0;
            if (EVP_DigestSign(ctx, NULL, &siglen, message.data(), message.size()) != 1)
                throw std::runtime_error("secure_crypto::ed25519_sign: query signature length failed");
            std::vector<uint8_t> signature(siglen);
            if (EVP_DigestSign(ctx, signature.data(), &siglen, message.data(), message.size()) != 1)
                throw std::runtime_error("secure_crypto::ed25519_sign: sign failed");
            signature.resize(siglen);

            EVP_PKEY_free(sk);
            EVP_MD_CTX_free(ctx);
            return signature;
        } catch (...) {
            EVP_PKEY_free(sk);
            EVP_MD_CTX_free(ctx);
            throw;
        }
    }

    bool ed25519_verify(
        const std::vector<uint8_t>& signature,
        const std::string& pk_path,
        const std::vector<uint8_t>& message)
    {
        // 读取公钥（io 层允许公钥文件是私钥 PEM，因为私钥文件里也含公钥部分）
        std::vector<uint8_t> pk_der = load_public_key_der_from_pem(pk_path);

        EVP_PKEY* pk = nullptr;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
            throw std::runtime_error("secure_crypto::ed25519_verify: EVP_MD_CTX_new failed");

        try {
            const unsigned char* p = pk_der.data();
            pk = d2i_PUBKEY(NULL, &p, static_cast<long>(pk_der.size()));
            if (!pk)
                throw std::runtime_error("secure_crypto::ed25519_verify: decode public key failed");

            if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pk) != 1)
                throw std::runtime_error("secure_crypto::ed25519_verify: EVP_DigestVerifyInit failed");

            int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                       message.data(), message.size());
            // ret: 1 验签通过, 0 验签失败（合法的"不匹配"）, <0 内部错误
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pk);
            if (ret < 0)
                throw std::runtime_error("secure_crypto::ed25519_verify: EVP_DigestVerify error");
            return ret == 1;
        } catch (...) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pk);
            throw;
        }
    }

}
