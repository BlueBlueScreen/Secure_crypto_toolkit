#include<gtest/gtest.h>
#include<secure_crypto/utils.hpp>
#include<secure_crypto/secure_random.hpp>
using namespace std;

TEST(Base64Test,BasicTest){
    vector<uint8_t> test_1=secure_crypto::random_bytes(32);
    string s=secure_crypto::base64_encode(test_1);
    vector<uint8_t> test_2=secure_crypto::base64_decode(s);
    EXPECT_EQ(test_1,test_2);
}

TEST(Base64Test, RFC4648Vectors) {
    struct { std::vector<uint8_t> input; std::string output; } cases[] = {
        {{}, ""},                                      // 空输入
        {{'f'}, "Zg=="},                               // 1 字节
        {{'f', 'o'}, "Zm8="},                         // 2 字节
        {{'f', 'o', 'o'}, "Zm9v"},                   // 3 字节
        {{'f', 'o', 'o', 'b'}, "Zm9vYg=="},          // 4 字节
        {{'f', 'o', 'o', 'b', 'a'}, "Zm9vYmE="},     // 5 字节
        {{'f', 'o', 'o', 'b', 'a', 'r'}, "Zm9vYmFy"} // 6 字节
    };

    for (const auto& c : cases) {
        EXPECT_EQ(secure_crypto::base64_encode(c.input), c.output);
        EXPECT_EQ(secure_crypto::base64_decode(c.output), c.input);
    }
}

TEST(Base64Test, InvalidInputs) {
    // 长度非法
    EXPECT_THROW(secure_crypto::base64_decode("ABC"), std::runtime_error);
    // 非法字符
    EXPECT_THROW(secure_crypto::base64_decode("AB$C"), std::runtime_error);
    // '=' 非末尾
    EXPECT_THROW(secure_crypto::base64_decode("A=BC"), std::runtime_error);
    // 过多 '='
    EXPECT_THROW(secure_crypto::base64_decode("===="), std::runtime_error);

}

TEST(HexTest,BasicTest){
    vector<uint8_t> test_1=secure_crypto::random_bytes(32);
    string s=secure_crypto::hex_encode(test_1);
    vector<uint8_t> test_2=secure_crypto::hex_decode(s);
    EXPECT_EQ(test_1,test_2);
}

TEST(HexTest, StandardVectors) {
    struct { std::vector<uint8_t> bin; std::string hex; } cases[] = {
        {{}, ""},
        {{0x00}, "00"},
        {{0xFF}, "ff"},
        {{0x12, 0x34, 0x56}, "123456"},
        {{0xAB, 0xCD, 0xEF}, "abcdef"}
    };
    for (const auto& c : cases) {
        EXPECT_EQ(secure_crypto::hex_encode(c.bin), c.hex);
        EXPECT_EQ(secure_crypto::hex_decode(c.hex), c.bin);
    }
}

TEST(HexTest, CaseInsensitive) {
    std::string upper = "A1B2C3";
    std::string lower = "a1b2c3";
    auto expected = secure_crypto::hex_decode(lower);
    EXPECT_EQ(secure_crypto::hex_decode(upper), expected);
}

TEST(HexTest, InvalidInputs) {
    // 奇数长度
    EXPECT_THROW(secure_crypto::hex_decode("A"), std::runtime_error);
    EXPECT_THROW(secure_crypto::hex_decode("123"), std::runtime_error);
    
    // 非法字符
    EXPECT_THROW(secure_crypto::hex_decode("AG"), std::runtime_error);
    EXPECT_THROW(secure_crypto::hex_decode("12!3"), std::runtime_error);
    EXPECT_THROW(secure_crypto::hex_decode("12 34"), std::runtime_error); // 空格
}

TEST(HexTest, EdgeInputs) {
    EXPECT_EQ(secure_crypto::hex_encode({}), "");
    EXPECT_EQ(secure_crypto::hex_decode(""), std::vector<uint8_t>{});
    
    // 单字节边界
    EXPECT_EQ(secure_crypto::hex_encode({0x00}), "00");
    EXPECT_EQ(secure_crypto::hex_encode({0xFF}), "ff");
}

TEST(HexTest, LargeInput) {
    auto data = secure_crypto::random_bytes(1024 * 1024); // 1MB
    auto decoded = secure_crypto::hex_decode(secure_crypto::hex_encode(data));
    EXPECT_EQ(data, decoded);
}