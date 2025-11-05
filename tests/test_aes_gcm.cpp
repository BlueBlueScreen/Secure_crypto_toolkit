#include "secure_crypto/secure_random.hpp"
#include<gtest/gtest.h>
#include<secure_crypto/aes_gcm.hpp>

TEST(AESGCMTest,Basic128Test){
    const vector<uint8_t> key=secure_crypto::random_bytes(16);
    const string plaintext="This is a test message";
    const vector<uint8_t> aad=secure_crypto::random_bytes(16);
    tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple=secure_crypto::aes_gcm_encrypt(key,plaintext,aad);
    string res=secure_crypto::aes_gcm_decrypt(key,cipher_tuple,aad);
    EXPECT_EQ(plaintext,res);
}

TEST(AESGCMTest,Basic256Test){
    const vector<uint8_t> key=secure_crypto::random_bytes(32);
    const string plaintext="This is a test message";
    const vector<uint8_t> aad=secure_crypto::random_bytes(16);
    tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple=secure_crypto::aes_gcm_encrypt(key,plaintext,aad);
    string res=secure_crypto::aes_gcm_decrypt(key,cipher_tuple,aad);
    EXPECT_EQ(plaintext,res);
}

TEST(AESGCMTest,NonceWrongTest){
    const vector<uint8_t> key=secure_crypto::random_bytes(16);
    const string plaintext="This is a test message";
    const vector<uint8_t> aad=secure_crypto::random_bytes(0);
    tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple=secure_crypto::aes_gcm_encrypt(key,plaintext,aad);
    vector<uint8_t> new_tag=secure_crypto::random_bytes(12);
    std::get<2>(cipher_tuple)=new_tag;
    EXPECT_THROW({
        secure_crypto::aes_gcm_decrypt(key, cipher_tuple, aad);
    }, runtime_error);
}
TEST(AESGCMTest,TagWrongTest){
    const vector<uint8_t> key=secure_crypto::random_bytes(16);
    const string plaintext="This is a test message";
    const vector<uint8_t> aad=secure_crypto::random_bytes(0);
    tuple<vector<uint8_t>,vector<uint8_t>,vector<uint8_t>> cipher_tuple=secure_crypto::aes_gcm_encrypt(key,plaintext,aad);
    vector<uint8_t> new_tag=secure_crypto::random_bytes(16);
    std::get<1>(cipher_tuple)=new_tag;
    EXPECT_THROW({
        secure_crypto::aes_gcm_decrypt(key, cipher_tuple, aad);
    }, runtime_error);
}