#include<secure_crypto/ed25519.hpp>
#include<secure_crypto/io.hpp>
#include<gtest/gtest.h>
#include<filesystem>
using namespace std;

TEST(Ed25519Test,Basictest){
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"ed25519";
    fs::create_directory(tmp);

    fs::path sk_path=tmp/"sk_path.pem";
    fs::path pk_path=tmp/"pk_path.pem";

    secure_crypto::sign_keygen(sk_path.string(),pk_path.string());
    string message="This is a message to be signed";
    vector<uint8_t> signature = secure_crypto::sign(sk_path.string(),message);
    bool res=secure_crypto::verify(signature,pk_path.string(),message);
    EXPECT_EQ(res,true);
    fs::remove_all(tmp);
}

TEST(Ed25519Test,Wrongtest1){
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"ed25519";
    fs::create_directory(tmp);

    fs::path sk_path=tmp/"sk_path.pem";
    fs::path pk_path=tmp/"pk_path.pem";

    secure_crypto::sign_keygen(sk_path.string(),pk_path.string());
    string message="This is a message to be signed";
    string message_wrong="This is not the message to be signed";
    vector<uint8_t> signature = secure_crypto::sign(sk_path.string(),message);
    bool res=secure_crypto::verify(signature,pk_path.string(),message_wrong);
    EXPECT_EQ(res,false);
    fs::remove_all(tmp);
}

TEST(Ed25519Test,Wrongtest2){
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"ed25519";
    fs::create_directory(tmp);

    fs::path sk_path=tmp/"sk_path.pem";
    fs::path pk_path=tmp/"pk_path.pem";

    secure_crypto::sign_keygen(sk_path.string(),pk_path.string());
    string message="This is a message to be signed";
    vector<uint8_t> signature = secure_crypto::sign(sk_path.string(),message);
    signature.back()^=1;
    bool res=secure_crypto::verify(signature,pk_path.string(),message);
    EXPECT_EQ(res,false);
    fs::remove_all(tmp);
}

TEST(Ed25519Test,SigLenTest){
    namespace fs=std::filesystem;
    fs::path tmp=fs::temp_directory_path()/"ed25519";
    fs::create_directory(tmp);

    fs::path sk_path=tmp/"sk_path.pem";
    fs::path pk_path=tmp/"pk_path.pem";

    secure_crypto::sign_keygen(sk_path.string(),pk_path.string());
    string message="This is a message to be signed";
    vector<uint8_t> signature = secure_crypto::sign(sk_path.string(),message);
    EXPECT_EQ(signature.size(),64);
    fs::remove_all(tmp);
}


