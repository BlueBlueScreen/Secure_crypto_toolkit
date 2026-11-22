#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <secure_crypto/x25519.hpp>
#include <secure_crypto/io.hpp>

namespace fs = std::filesystem;

// 每个用例独立临时目录，避免相互污染
class X25519Test : public ::testing::Test {
protected:
    void SetUp() override {
        tmp = fs::temp_directory_path() /
              ("sct_x25519_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        fs::remove_all(tmp);
        fs::create_directories(tmp);
    }
    void TearDown() override { fs::remove_all(tmp); }
    fs::path tmp;
};

TEST_F(X25519Test, SharedSecretAgreement) {
    // 经典双边密钥协商：Alice 用(自己的私钥, Bob 的公钥)，Bob 用(自己的私钥, Alice 的公钥)，应得到同一共享密钥
    const auto a_sk = (tmp / "alice_sk.pem").string();
    const auto a_pk = (tmp / "alice_pk.pem").string();
    const auto b_sk = (tmp / "bob_sk.pem").string();
    const auto b_pk = (tmp / "bob_pk.pem").string();

    secure_crypto::x25519_keygen(a_sk, a_pk);
    secure_crypto::x25519_keygen(b_sk, b_pk);

    auto k_alice = secure_crypto::x25519_derive(a_sk, b_pk);
    auto k_bob = secure_crypto::x25519_derive(b_sk, a_pk);
    EXPECT_EQ(k_alice, k_bob);
    EXPECT_EQ(k_alice.size(), 32u); // X25519 共享密钥固定 32 字节
}

TEST_F(X25519Test, MissingFile) {
    EXPECT_THROW(secure_crypto::x25519_derive("no_such_file.pem", "no_such_file2.pem"),
                 std::runtime_error);
}

TEST_F(X25519Test, EmptyFile) {
    auto sk = (tmp / "sk.pem").string();
    auto pk = (tmp / "pk.pem").string();
    std::ofstream(sk) << "";
    std::ofstream(pk) << "";
    EXPECT_THROW(secure_crypto::x25519_derive(sk, pk), std::runtime_error);
}

TEST_F(X25519Test, CorruptedFile) {
    auto sk = (tmp / "corrupt_sk.pem").string();
    auto pk = (tmp / "corrupt_pk.pem").string();
    std::ofstream(sk) << "Not a valid pem";
    std::ofstream(pk) << "Not a valid pem";
    EXPECT_THROW(secure_crypto::x25519_derive(sk, pk), std::runtime_error);
}

TEST_F(X25519Test, MismatchedKeys) {
    // 与不同对端协商应得到不同的共享密钥
    const auto a_sk = (tmp / "A_sk.pem").string();
    const auto a_pk = (tmp / "A_pk.pem").string();
    const auto b_sk = (tmp / "B_sk.pem").string();
    const auto b_pk = (tmp / "B_pk.pem").string();
    const auto c_sk = (tmp / "C_sk.pem").string();
    const auto c_pk = (tmp / "C_pk.pem").string();

    secure_crypto::x25519_keygen(a_sk, a_pk);
    secure_crypto::x25519_keygen(b_sk, b_pk);
    secure_crypto::x25519_keygen(c_sk, c_pk);

    auto k1 = secure_crypto::x25519_derive(a_sk, b_pk);
    auto k2 = secure_crypto::x25519_derive(a_sk, c_pk);
    EXPECT_NE(k1, k2);
}

TEST_F(X25519Test, DeterministicDerive) {
    // 同一密钥对的派生是确定性的（纯数学运算，不含随机性）
    const auto a_sk = (tmp / "A_sk.pem").string();
    const auto a_pk = (tmp / "A_pk.pem").string();
    const auto b_sk = (tmp / "B_sk.pem").string();
    const auto b_pk = (tmp / "B_pk.pem").string();

    secure_crypto::x25519_keygen(a_sk, a_pk);
    secure_crypto::x25519_keygen(b_sk, b_pk);

    auto k1 = secure_crypto::x25519_derive(a_sk, b_pk);
    auto k2 = secure_crypto::x25519_derive(a_sk, b_pk);
    EXPECT_EQ(k1, k2);
}

TEST_F(X25519Test, KeypairRandomness) {
    // 两次生成的密钥对应完全不同
    secure_crypto::x25519_keygen((tmp / "1_sk.pem").string(), (tmp / "1_pk.pem").string());
    secure_crypto::x25519_keygen((tmp / "2_sk.pem").string(), (tmp / "2_pk.pem").string());

    auto pk1 = secure_crypto::load_public_key_der_from_pem((tmp / "1_pk.pem").string());
    auto pk2 = secure_crypto::load_public_key_der_from_pem((tmp / "2_pk.pem").string());
    EXPECT_NE(pk1, pk2);
}

TEST_F(X25519Test, UnicodePath) {
    // 路径含非 ASCII 字符时应正常工作
    fs::path dir = tmp / u8"测试目录";
    fs::create_directories(dir);
    auto sk = (dir / u8"私钥.pem").string();
    auto pk = (dir / u8"公钥.pem").string();

    secure_crypto::x25519_keygen(sk, pk);
    // 用自己的私钥 + 自己的公钥派生也是合法运算，得到 32 字节共享密钥
    auto k = secure_crypto::x25519_derive(sk, pk);
    EXPECT_EQ(k.size(), 32u);
}

TEST_F(X25519Test, TruncatedDER) {
    // 公钥 DER 被截断后必须报错，而不是派生出错误密钥
    auto sk = (tmp / "sk.pem").string();
    auto pk = (tmp / "pk.pem").string();
    secure_crypto::x25519_keygen(sk, pk);

    auto der = secure_crypto::load_public_key_der_from_pem(pk);
    der.resize(der.size() / 2);
    // 把截断的 DER 写成"公钥 PEM"（模拟被篡改/损坏的密钥文件）
    // 直接测试 io 层：截断 DER 无法通过 load_private/load_public 的解码路径
    std::ofstream(pk + ".der", std::ios::binary)
        .write(reinterpret_cast<const char*>(der.data()), der.size());
    EXPECT_THROW(secure_crypto::x25519_derive(sk, pk + ".der"), std::runtime_error);
}
