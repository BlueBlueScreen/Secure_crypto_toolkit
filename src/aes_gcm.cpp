#include <openssl/evp.h>
#include <stdexcept>
#include <secure_crypto/aes_gcm.hpp>
#include <secure_crypto/secure_random.hpp>

namespace secure_crypto {

    // GCM 标准推荐 12 字节 nonce、16 字节认证标签，此处写死为安全默认值
    static constexpr size_t GCM_NONCE_LEN = 12;
    static constexpr size_t GCM_TAG_LEN = 16;

    GcmCiphertext aes_gcm_encrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad)
    {
        // 只接受 AES-128 / AES-256，其他长度直接拒绝
        if (key.size() != 16 && key.size() != 32) {
            throw std::runtime_error("secure_crypto::aes_gcm_encrypt: wrong key length");
        }

        // 根据密钥长度选择算法
        const EVP_CIPHER* cipher = (key.size() == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("secure_crypto::aes_gcm_encrypt: EVP_CIPHER_CTX_new failed");

        try {
            // nonce 每次加密都从 CSPRNG 重新生成（GCM 下 nonce 重用会同时泄露明文和密钥）
            GcmCiphertext out;
            out.nonce = random_bytes(GCM_NONCE_LEN);

            if (EVP_EncryptInit_ex(ctx, cipher, NULL, key.data(), out.nonce.data()) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_encrypt: EncryptInit_ex failed");

            // 先喂 AAD（只认证不加密），NULL 输出表示这一步不产生密文
            if (!aad.empty()) {
                int aad_outlen = 0;
                if (EVP_EncryptUpdate(ctx, NULL, &aad_outlen, aad.data(),
                                      static_cast<int>(aad.size())) != 1)
                    throw std::runtime_error("secure_crypto::aes_gcm_encrypt: update AAD failed");
            }

            // 加密明文。GCM 是流式模式，输出长度 = 输入长度；
            // 多留一个分组只是防御性余量
            std::vector<uint8_t> buf(plaintext.size() + EVP_CIPHER_block_size(cipher));
            int outlen = 0;
            int cipherlen = 0;
            if (EVP_EncryptUpdate(ctx, buf.data(), &outlen, plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_encrypt: EncryptUpdate failed");
            cipherlen += outlen;

            outlen = 0;
            if (EVP_EncryptFinal_ex(ctx, buf.data() + cipherlen, &outlen) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_encrypt: EncryptFinal_ex failed");
            cipherlen += outlen;

            // 取认证标签
            out.tag.resize(GCM_TAG_LEN);
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, out.tag.data()) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_encrypt: get tag failed");

            buf.resize(cipherlen);
            out.ciphertext = std::move(buf);

            EVP_CIPHER_CTX_free(ctx);
            return out;
        } catch (...) {
            // 保证出错路径也释放上下文
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }

    std::vector<uint8_t> aes_gcm_decrypt(
        const std::vector<uint8_t>& key,
        const GcmCiphertext& ct,
        const std::vector<uint8_t>& aad)
    {
        if (ct.tag.size() != GCM_TAG_LEN || ct.nonce.size() != GCM_NONCE_LEN) {
            throw std::runtime_error("secure_crypto::aes_gcm_decrypt: wrong tag or nonce length");
        }
        if (key.size() != 16 && key.size() != 32) {
            throw std::runtime_error("secure_crypto::aes_gcm_decrypt: wrong key length");
        }

        const EVP_CIPHER* cipher = (key.size() == 16) ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("secure_crypto::aes_gcm_decrypt: EVP_CIPHER_CTX_new failed");

        try {
            if (EVP_DecryptInit_ex(ctx, cipher, NULL, key.data(), ct.nonce.data()) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_decrypt: DecryptInit_ex failed");

            if (!aad.empty()) {
                int aad_in = 0;
                if (EVP_DecryptUpdate(ctx, NULL, &aad_in, aad.data(),
                                      static_cast<int>(aad.size())) != 1)
                    throw std::runtime_error("secure_crypto::aes_gcm_decrypt: update AAD failed");
            }

            int len = 0;
            int ptext_len = 0;
            std::vector<uint8_t> ptext(ct.ciphertext.size() + EVP_CIPHER_block_size(cipher));
            if (EVP_DecryptUpdate(ctx, ptext.data(), &len, ct.ciphertext.data(),
                                  static_cast<int>(ct.ciphertext.size())) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_decrypt: DecryptUpdate failed");
            ptext_len += len;

            // 解密模式下 SET_TAG 不是设置"正确标签"，而是把期望值交给 OpenSSL 比对；
            // 必须在 DecryptFinal_ex 之前设置，真正的校验发生在 Final。
            // （OpenSSL 该接口签名无 const，但 SET_TAG 只读缓冲区，const_cast 安全）
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                    static_cast<int>(ct.tag.size()),
                                    const_cast<uint8_t*>(ct.tag.data())) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_decrypt: set tag failed");

            len = 0;
            // Final 返回失败 = 完整性校验不通过（密文/标签/AAD 任一被篡改或密钥错误）
            if (EVP_DecryptFinal_ex(ctx, ptext.data() + ptext_len, &len) != 1)
                throw std::runtime_error("secure_crypto::aes_gcm_decrypt: authentication failed");
            ptext_len += len;

            ptext.resize(ptext_len);
            EVP_CIPHER_CTX_free(ctx);
            return ptext;
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }

}
