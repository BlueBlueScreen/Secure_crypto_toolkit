#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <secure_crypto/hkdf.hpp>

using std::vector;
using std::string;

static vector<uint8_t> unhex(const string& hex) {
    vector<uint8_t> out;
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), NULL, 16)));
    }
    return out;
}

// RFC 5869 A.1 Test Case 1（SHA-256）
TEST(HKDFTest, Rfc5869TestCase1) {
    const vector<uint8_t> ikm(22, 0x0b);
    const vector<uint8_t> salt = unhex("000102030405060708090a0b0c");
    const vector<uint8_t> info = unhex("f0f1f2f3f4f5f6f7f8f9");

    const vector<uint8_t> okm = secure_crypto::hkdf_sha256(ikm, 42, salt, info);
    const vector<uint8_t> expected = unhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865");
    EXPECT_EQ(okm, expected);
}

// RFC 5869 A.1 Test Case 3：salt / info 省略（空 salt 按 RFC 应补 HashLen 个 0）
TEST(HKDFTest, Rfc5869TestCase3) {
    const vector<uint8_t> ikm(22, 0x0b);
    const vector<uint8_t> okm = secure_crypto::hkdf_sha256(ikm, 42);
    const vector<uint8_t> expected = unhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8");
    EXPECT_EQ(okm, expected);
}

TEST(HKDFTest, EmptySaltAndInfoDefault) {
    // 默认参数（不传 salt / info）应与显式传空一致
    const vector<uint8_t> ikm(22, 0x0b);
    auto k1 = secure_crypto::hkdf_sha256(ikm, 32);
    auto k2 = secure_crypto::hkdf_sha256(ikm, 32, {}, {});
    EXPECT_EQ(k1, k2);
}

TEST(HKDFTest, EmptyIkmRejected) {
    // 空的输入密钥材料没有安全意义，应报错而不是产出全零密钥
    EXPECT_THROW(secure_crypto::hkdf_sha256({}, 32, vector<uint8_t>(13, 0x01),
                                            vector<uint8_t>(10, 0x02)),
                 std::runtime_error);
}

TEST(HKDFTest, TooLongOutputRejected) {
    // RFC 5869 限制 L <= 255 * HashLen
    const vector<uint8_t> ikm(22, 0x01);
    EXPECT_THROW(secure_crypto::hkdf_sha256(ikm, 255 * 32 + 1,
                                            vector<uint8_t>(13, 0x02)),
                 std::runtime_error);
}

TEST(HKDFTest, Deterministic) {
    const vector<uint8_t> ikm(22, 0x01);
    const vector<uint8_t> salt(13, 0x02);
    const vector<uint8_t> info(10, 0x03);
    EXPECT_EQ(secure_crypto::hkdf_sha256(ikm, 56, salt, info),
              secure_crypto::hkdf_sha256(ikm, 56, salt, info));
}

TEST(HKDFTest, InputSensitivity) {
    // salt / info 各改 1 bit，输出应完全不同（雪崩性）
    const vector<uint8_t> ikm(22, 0x01);
    vector<uint8_t> salt(13, 0x02);
    vector<uint8_t> info(10, 0x03);
    auto okm1 = secure_crypto::hkdf_sha256(ikm, 56, salt, info);
    salt[0] ^= 0x01;
    auto okm2 = secure_crypto::hkdf_sha256(ikm, 56, salt, info);
    EXPECT_NE(okm1, okm2);
    info[0] ^= 0x01;
    auto okm3 = secure_crypto::hkdf_sha256(ikm, 56, salt, info);
    EXPECT_NE(okm2, okm3);
}
