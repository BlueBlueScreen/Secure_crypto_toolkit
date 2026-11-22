#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <vector>
#include <secure_crypto/ed25519.hpp>

namespace fs = std::filesystem;

static std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

class Ed25519Test : public ::testing::Test {
protected:
    void SetUp() override {
        tmp = fs::temp_directory_path() /
              ("sct_ed25519_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        fs::remove_all(tmp);
        fs::create_directories(tmp);
        sk = (tmp / "sk.pem").string();
        pk = (tmp / "pk.pem").string();
        secure_crypto::ed25519_keygen(sk, pk);
    }
    void TearDown() override { fs::remove_all(tmp); }
    fs::path tmp;
    std::string sk, pk;
};

TEST_F(Ed25519Test, BasicTest) {
    const auto message = to_bytes("This is a message to be signed");
    auto signature = secure_crypto::ed25519_sign(sk, message);
    EXPECT_TRUE(secure_crypto::ed25519_verify(signature, pk, message));
}

TEST_F(Ed25519Test, SignatureLength) {
    // Ed25519 签名长度固定 64 字节
    auto signature = secure_crypto::ed25519_sign(sk, to_bytes("hello"));
    EXPECT_EQ(signature.size(), 64u);
}

TEST_F(Ed25519Test, WrongMessageTest) {
    auto signature = secure_crypto::ed25519_sign(sk, to_bytes("original message"));
    // 消息被改一个字符，验签必须失败
    EXPECT_FALSE(secure_crypto::ed25519_verify(signature, pk, to_bytes("originaL message")));
}

TEST_F(Ed25519Test, TamperedSignatureTest) {
    auto signature = secure_crypto::ed25519_sign(sk, to_bytes("message"));
    signature.back() ^= 0x01; // 翻转签名最后一个比特
    EXPECT_FALSE(secure_crypto::ed25519_verify(signature, pk, to_bytes("message")));
}

TEST_F(Ed25519Test, WrongPublicKeyTest) {
    // 用别人的公钥验签必须失败
    auto pk2 = (tmp / "pk2.pem").string();
    secure_crypto::ed25519_keygen((tmp / "sk2.pem").string(), pk2);
    auto signature = secure_crypto::ed25519_sign(sk, to_bytes("message"));
    EXPECT_FALSE(secure_crypto::ed25519_verify(signature, pk2, to_bytes("message")));
}

TEST_F(Ed25519Test, MissingKeyFile) {
    EXPECT_THROW(secure_crypto::ed25519_sign((tmp / "nonexistent.pem"), to_bytes("m")),
                 std::runtime_error);
}
