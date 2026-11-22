#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <secure_crypto/secure_hash.hpp>
#include <secure_crypto/utils.hpp>

using secure_crypto::hex_decode;
using secure_crypto::hex_encode;

// ---------- SHA-2 家族（NIST FIPS 180-4，示例来自 NIST 官方示例） ----------

TEST(SHA2Test, NistVectorAbc) {
    const std::vector<uint8_t> msg = {'a', 'b', 'c'};

    EXPECT_EQ(hex_encode(secure_crypto::sha256(msg)),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(hex_encode(secure_crypto::sha384(msg)),
              "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
              "8086072ba1e7cc2358baeca134c825a7");
    EXPECT_EQ(hex_encode(secure_crypto::sha512(msg)),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(SHA2Test, NistVectorEmpty) {
    const std::vector<uint8_t> empty;

    EXPECT_EQ(hex_encode(secure_crypto::sha256(empty)),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(hex_encode(secure_crypto::sha512(empty)),
              "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
              "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

// 56 字节消息：正好触发 SHA-2 长度分组的边界（需要补两个分组）
TEST(SHA2Test, NistVectorLongMessage) {
    const std::string s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const std::vector<uint8_t> msg(s.begin(), s.end());

    EXPECT_EQ(hex_encode(secure_crypto::sha256(msg)),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(SHA2Test, ConcatEqualsOneShot) {
    // 分段拼接哈希应与对拼接结果做一次性哈希一致；参数允许 string 与字节串混用
    std::vector<uint8_t> joined = {'a', 'b', 'c', 'd', 'e', 'f'};
    EXPECT_EQ(secure_crypto::sha256_concat(std::string("abc"), std::string("def")),
              secure_crypto::sha256(joined));
    // 相同字节，无论以 string 还是字节串传入，结果一致
    const std::vector<uint8_t> p1 = {'a', 'b', 'c'}, p2 = {'d', 'e', 'f'};
    EXPECT_EQ(secure_crypto::sha512_concat(p1, p2),
              secure_crypto::sha512_concat(std::string("abc"), std::string("def")));
}

TEST(SHA2Test, DigestLength) {
    const std::vector<uint8_t> msg = {'a'};
    EXPECT_EQ(secure_crypto::sha256(msg).size(), 32u);
    EXPECT_EQ(secure_crypto::sha384(msg).size(), 48u);
    EXPECT_EQ(secure_crypto::sha512(msg).size(), 64u);
}

// ---------- SHA-3 家族（NIST FIPS 202，示例来自 NIST 官方示例） ----------

TEST(SHA3Test, NistVectorAbc) {
    const std::vector<uint8_t> msg = {'a', 'b', 'c'};

    EXPECT_EQ(hex_encode(secure_crypto::sha3_256(msg)),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    EXPECT_EQ(hex_encode(secure_crypto::sha3_384(msg)),
              "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
              "98d88cea927ac7f539f1edf228376d25");
    EXPECT_EQ(hex_encode(secure_crypto::sha3_512(msg)),
              "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
              "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

TEST(SHA3Test, NistVectorEmpty) {
    const std::vector<uint8_t> empty;

    EXPECT_EQ(hex_encode(secure_crypto::sha3_256(empty)),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    EXPECT_EQ(hex_encode(secure_crypto::sha3_512(empty)),
              "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
              "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

TEST(SHA3Test, ConcatEqualsOneShot) {
    const std::string part1 = "ab";
    const std::string part2 = "c";
    const std::vector<uint8_t> joined = {'a', 'b', 'c'};
    EXPECT_EQ(secure_crypto::sha3_256_concat(part1, part2),
              secure_crypto::sha3_256(joined));
}

TEST(SHA3Test, Sha3DiffersFromSha2) {
    // 相同输入下 SHA3-256 与 SHA-256 输出必须不同（确认不是忘了换算法对象）
    const std::vector<uint8_t> msg = {'a', 'b', 'c'};
    EXPECT_NE(secure_crypto::sha3_256(msg), secure_crypto::sha256(msg));
}
