#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <secure_crypto/aes_gcm.hpp>
#include <secure_crypto/secure_random.hpp>

using secure_crypto::aes_gcm_decrypt;
using secure_crypto::aes_gcm_encrypt;
using secure_crypto::GcmCiphertext;
using secure_crypto::random_bytes;

// 字节串转换辅助函数
static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

TEST(AESGCMTest, Basic128Test) {
    const std::vector<uint8_t> key = random_bytes(16);
    const std::vector<uint8_t> plaintext = to_bytes("This is a test message");
    const std::vector<uint8_t> aad = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, plaintext, aad);
    EXPECT_EQ(aes_gcm_decrypt(key, ct, aad), plaintext);
}

TEST(AESGCMTest, Basic256Test) {
    const std::vector<uint8_t> key = random_bytes(32);
    const std::vector<uint8_t> plaintext = to_bytes("This is a test message");
    const std::vector<uint8_t> aad = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, plaintext, aad);
    EXPECT_EQ(aes_gcm_decrypt(key, ct, aad), plaintext);
}

TEST(AESGCMTest, NonceAndTagLength) {
    const std::vector<uint8_t> key = random_bytes(32);
    GcmCiphertext ct = aes_gcm_encrypt(key, to_bytes("hello"), {});
    // 安全默认值：96bit nonce、128bit 标签、密文与明文等长
    EXPECT_EQ(ct.nonce.size(), 12u);
    EXPECT_EQ(ct.tag.size(), 16u);
    EXPECT_EQ(ct.ciphertext.size(), 5u);
}

TEST(AESGCMTest, EmptyPlaintext) {
    const std::vector<uint8_t> key = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, {}, to_bytes("aad only"));
    EXPECT_TRUE(aes_gcm_decrypt(key, ct, to_bytes("aad only")).empty());
}

TEST(AESGCMTest, NonceIsFreshPerEncryption) {
    // 同一密钥、同一明文两次加密，nonce 必须不同，密文也应不同
    const std::vector<uint8_t> key = random_bytes(16);
    const std::vector<uint8_t> plaintext = to_bytes("same input twice");
    GcmCiphertext ct1 = aes_gcm_encrypt(key, plaintext, {});
    GcmCiphertext ct2 = aes_gcm_encrypt(key, plaintext, {});
    EXPECT_NE(ct1.nonce, ct2.nonce);
    EXPECT_NE(ct1.ciphertext, ct2.ciphertext);
}

TEST(AESGCMTest, WrongNonceTest) {
    const std::vector<uint8_t> key = random_bytes(16);
    const std::vector<uint8_t> plaintext = to_bytes("This is a test message");
    GcmCiphertext ct = aes_gcm_encrypt(key, plaintext, {});
    ct.nonce = random_bytes(12);
    EXPECT_THROW(aes_gcm_decrypt(key, ct, {}), std::runtime_error);
}

TEST(AESGCMTest, TagWrongTest) {
    const std::vector<uint8_t> key = random_bytes(16);
    const std::vector<uint8_t> plaintext = to_bytes("This is a test message");
    GcmCiphertext ct = aes_gcm_encrypt(key, plaintext, {});
    ct.tag = random_bytes(16);
    EXPECT_THROW(aes_gcm_decrypt(key, ct, {}), std::runtime_error);
}

TEST(AESGCMTest, CiphertextTamperedTest) {
    // 翻转密文任意一个比特，认证都应失败
    const std::vector<uint8_t> key = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, to_bytes("tamper me please"), {});
    ct.ciphertext[3] ^= 0x01;
    EXPECT_THROW(aes_gcm_decrypt(key, ct, {}), std::runtime_error);
}

TEST(AESGCMTest, AadMismatchTest) {
    // AAD 虽不加密，但参与认证；解密时 AAD 不一致必须失败
    const std::vector<uint8_t> key = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, to_bytes("message"), to_bytes("header-A"));
    EXPECT_THROW(aes_gcm_decrypt(key, ct, to_bytes("header-B")), std::runtime_error);
}

TEST(AESGCMTest, WrongKeyTest) {
    const std::vector<uint8_t> key = random_bytes(16);
    GcmCiphertext ct = aes_gcm_encrypt(key, to_bytes("message"), {});
    EXPECT_THROW(aes_gcm_decrypt(random_bytes(16), ct, {}), std::runtime_error);
}

TEST(AESGCMTest, WrongKeyLengthTest) {
    // 只接受 16/32 字节密钥，其他长度（如被降级的 8 字节）直接拒绝
    EXPECT_THROW(aes_gcm_encrypt(random_bytes(8), to_bytes("x"), {}), std::runtime_error);
    EXPECT_THROW(aes_gcm_encrypt(random_bytes(24), to_bytes("x"), {}), std::runtime_error);
}
