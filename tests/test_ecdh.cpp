#include<secure_crypto/ecdh.hpp>
#include<secure_crypto/io.hpp>
#include<gtest/gtest.h>
#include<filesystem>
using namespace std;

TEST(ECDHTest,BasicTest){
    //创建临时目录，避免目录污染
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"ecdh_test_XXXXXX";
    fs::create_directory(tmp);
    //拼接路径
    fs::path alice_sk = tmp / "Alice_sk.pem";
    fs::path alice_pk = tmp / "Alice_pk.pem";
    fs::path bob_sk   = tmp / "Bob_sk.pem";
    fs::path bob_pk   = tmp / "Bob_pk.pem";

    //进行测试
    secure_crypto::ecdh_create_key(alice_sk.string(),alice_pk.string());
    secure_crypto::ecdh_create_key(bob_sk.string(),bob_pk.string());
    vector<uint8_t> K_0=secure_crypto::ecdh_derive_key(alice_sk.string(),bob_pk.string());
    vector<uint8_t> K_1=secure_crypto::ecdh_derive_key(bob_sk.string(),alice_pk.string());
    EXPECT_EQ(K_0,K_1);

    //清理目录
    fs::remove_all(tmp);
}

TEST(ECDHTest, MissingFile) {
    EXPECT_THROW(secure_crypto::ecdh_derive_key("no_such_file.pem", "no_such_file2.pem"),
                 std::runtime_error);
}

TEST(ECDHTest, EmptyFile) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "empty_test";
    fs::create_directory(tmp);

    fs::path empty_sk = tmp / "sk.pem";
    fs::path empty_pk = tmp / "pk.pem";

    std::ofstream(empty_sk) << "";
    std::ofstream(empty_pk) << "";

    EXPECT_THROW(secure_crypto::ecdh_derive_key(empty_sk.string(), empty_pk.string()),
                 std::runtime_error);

    fs::remove_all(tmp);
}

TEST(ECDHTest,CorruptedFile){
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"corrupt_ecdh";
    fs::create_directory(tmp);

    fs::path corrupt_sk=tmp/"corrupt_pem";
    fs::path corrupt_pk=tmp/"corrupt_pem";
    
    auto write=[&](fs::path p){ofstream(p)<<"Not a valid pem";};
    write(corrupt_pk);
    write(corrupt_sk);

    EXPECT_THROW({secure_crypto::ecdh_derive_key(corrupt_sk.string(),corrupt_pk.string());},runtime_error);

    fs::remove_all(tmp);
}

TEST(ECDHTest, MismatchedKeys) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "mismatch";
    fs::create_directory(tmp);

    fs::path A_sk = tmp / "A_sk.pem";
    fs::path A_pk = tmp / "A_pk.pem";
    fs::path B_sk = tmp / "B_sk.pem";
    fs::path B_pk = tmp / "B_pk.pem";
    fs::path C_sk = tmp / "C_sk.pem";
    fs::path C_pk = tmp / "C_pk.pem";

    secure_crypto::ecdh_create_key(A_sk.string(), A_pk.string());
    secure_crypto::ecdh_create_key(B_sk.string(), B_pk.string());
    secure_crypto::ecdh_create_key(C_sk.string(), C_pk.string());

    auto K1 = secure_crypto::ecdh_derive_key(A_sk.string(), B_pk.string());
    auto K2 = secure_crypto::ecdh_derive_key(A_sk.string(), C_pk.string());

    EXPECT_NE(K1, K2);

    fs::remove_all(tmp);
}

TEST(ECDHTest, DeterministicDerive) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "derive_consistency";
    fs::create_directory(tmp);

    fs::path A_sk = tmp / "A_sk.pem";
    fs::path A_pk = tmp / "A_pk.pem";
    fs::path B_sk = tmp / "B_sk.pem";
    fs::path B_pk = tmp / "B_pk.pem";

    secure_crypto::ecdh_create_key(A_sk.string(), A_pk.string());
    secure_crypto::ecdh_create_key(B_sk.string(), B_pk.string());

    auto K1 = secure_crypto::ecdh_derive_key(A_sk.string(), B_pk.string());
    auto K2 = secure_crypto::ecdh_derive_key(A_sk.string(), B_pk.string());
    auto K3 = secure_crypto::ecdh_derive_key(A_sk.string(), B_pk.string());

    EXPECT_EQ(K1, K2);
    EXPECT_EQ(K1, K3);

    fs::remove_all(tmp);
}

TEST(ECDHTest, KeypairRandomness) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "rand";
    fs::create_directory(tmp);

    fs::path s1 = tmp / "1_sk.pem";
    fs::path p1 = tmp / "1_pk.pem";
    fs::path s2 = tmp / "2_sk.pem";
    fs::path p2 = tmp / "2_pk.pem";

    secure_crypto::ecdh_create_key(s1.string(), p1.string());
    secure_crypto::ecdh_create_key(s2.string(), p2.string());

    auto pk1 = secure_crypto::load_public_key_der_from_pem(p1.string());
    auto pk2 = secure_crypto::load_public_key_der_from_pem(p2.string());

    EXPECT_NE(pk1, pk2);

    fs::remove_all(tmp);
}


TEST(ECDHTest, UnicodePath) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / u8"测试目录";
    fs::create_directory(tmp);

    fs::path sk = tmp / u8"私钥.pem";
    fs::path pk = tmp / u8"公钥.pem";

    secure_crypto::ecdh_create_key(sk.string(), pk.string());
    auto k = secure_crypto::ecdh_derive_key(sk.string(), pk.string()); // 自派生应抛错

    fs::remove_all(tmp);
}

TEST(ECDHTest, TruncatedDER) {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "trunc";
    fs::create_directory(tmp);

    fs::path sk = tmp / "sk.pem";
    fs::path pk = tmp / "pk.der";

    secure_crypto::ecdh_create_key(sk.string(), pk.string());

    auto der = secure_crypto::load_public_key_der_from_pem(pk.string());
    der.resize(5);

    std::ofstream(pk) << std::string(der.begin(), der.end());

    EXPECT_THROW(secure_crypto::ecdh_derive_key(sk.string(), pk.string()),
                 std::runtime_error);

    fs::remove_all(tmp);
}


