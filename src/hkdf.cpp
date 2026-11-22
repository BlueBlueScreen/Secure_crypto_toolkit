#include <secure_crypto/hkdf.hpp>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

namespace secure_crypto {

    std::vector<uint8_t> hkdf_sha256(
        const std::vector<uint8_t>& ikm,
        size_t n,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info)
    {
        // OpenSSL 3.0 起 KDF 走 EVP_KDF 这个新框架
        EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (!kdf)
            throw std::runtime_error("secure_crypto::hkdf_sha256: EVP_KDF_fetch failed");

        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
        if (!ctx) {
            EVP_KDF_free(kdf);
            throw std::runtime_error("secure_crypto::hkdf_sha256: EVP_KDF_CTX_new failed");
        }

        try {
            int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 const_cast<char*>("SHA256"), 0),
                OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  const_cast<uint8_t*>(ikm.data()), ikm.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                  const_cast<uint8_t*>(salt.data()), salt.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                  const_cast<uint8_t*>(info.data()), info.size()),
                OSSL_PARAM_END
            };

            std::vector<uint8_t> key(n);
            if (EVP_KDF_derive(ctx, key.data(), n, params) != 1) {
                throw std::runtime_error("secure_crypto::hkdf_sha256: EVP_KDF_derive failed");
            }

            EVP_KDF_CTX_free(ctx);
            EVP_KDF_free(kdf);
            return key;
        } catch (...) {
            EVP_KDF_CTX_free(ctx);
            EVP_KDF_free(kdf);
            throw;
        }
    }

}
