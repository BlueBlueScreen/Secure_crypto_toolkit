#include<secure_crypto/hkdf.hpp>
#include<gtest/gtest.h>
#include <sys/types.h>

//采用RFC5869标准测试向量SHA-256组进行测试

TEST(HKDFTest,StandartRFCTestSha_256){
    const std::vector<uint8_t> ikm = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const std::vector<uint8_t> salt = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    }; // 13 bytes
    const std::vector<uint8_t> info = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
    0xf5, 0xf6, 0xf7, 0xf8, 0xf9
}; // 10 bytes
    size_t n=42;

    vector<uint8_t> key=secure_crypto::hkdf_sha256(ikm, n,salt,info);
    const std::vector<uint8_t> okm_expected = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

    EXPECT_EQ(key,okm_expected);
}

TEST(HKDFTest,EmptySaltTest){
    const vector<uint8_t> ikm(22,0x0b);
    const vector<uint8_t> salt;
    const vector<uint8_t> info(10,0x0b);
    auto okm=secure_crypto::hkdf_sha256(ikm, 42,salt,info);
    EXPECT_EQ(okm.size(),42);
}

TEST(HKDFTest, EmptyInfoTest) {
    vector<uint8_t> ikm(22, 0x0b);
    vector<uint8_t> salt(13, 0x01);
    vector<uint8_t> info; // 空
    auto okm = secure_crypto::hkdf_sha256(ikm, 32, salt, info);
    EXPECT_EQ(okm.size(), 32);
}

TEST(HKDFTest, EmptyKeyTest) {
    vector<uint8_t> ikm;
    vector<uint8_t> salt(13, 0x01);
    vector<uint8_t> info(10, 0x02);
    EXPECT_THROW({
        auto okm = secure_crypto::hkdf_sha256(ikm, 32, salt, info);
    }, std::runtime_error);
}

TEST(HKDFTest,TooLongKeyTest){
    const vector<uint8_t> ikm(22,0x01);
    const vector<uint8_t> salt(13,0x02);
    const vector<uint8_t> info(10,0x03);
    //HKDF要求的长度是不大于255*hash_len
    size_t n=255*32+1;
        EXPECT_THROW({
        auto okm = secure_crypto::hkdf_sha256(ikm, n, salt, info);
    }, std::runtime_error);
}

TEST(HKDFTest,ConsistencyTest){
    const vector<uint8_t> ikm(22,0x01);
    const vector<uint8_t> salt(13,0x02);
    const vector<uint8_t> info(10,0x03);
    //HKDF要求的长度是不大于255*hash_len
    auto okm1=secure_crypto::hkdf_sha256(ikm, 56,salt,info);
    auto okm2=secure_crypto::hkdf_sha256(ikm, 56,salt,info);
    EXPECT_EQ(okm1,okm2);
}

TEST(HKDFTest,SensitivityTest){
    const vector<uint8_t> ikm(22,0x01);
    const vector<uint8_t> salt(13,0x02);
    vector<uint8_t> info(10,0x03);
    //HKDF要求的长度是不大于255*hash_len
    auto okm1=secure_crypto::hkdf_sha256(ikm, 56,salt,info);
    info[0]^=0x01;
    auto okm2=secure_crypto::hkdf_sha256(ikm, 56,salt,info);
    EXPECT_NE(okm1,okm2);
}


