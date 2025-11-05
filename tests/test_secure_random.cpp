#include<gtest/gtest.h>
#include<secure_crypto/secure_random.hpp>

TEST(SecureRandomTest,RandomBytesZero){
    auto r=secure_crypto::random_bytes(0);
    EXPECT_TRUE(r.empty());
}
TEST(SecureRandomTest,RandomBytes512)
{
    auto r=secure_crypto::random_bytes(512);
    EXPECT_EQ(r.size(),512);
}

TEST(SecureRandomTest,RandomBytes32){
    auto r=secure_crypto::rand_uint32();
    EXPECT_EQ(sizeof(r),4);
}

TEST(SecureRandomTest,RandomBytes64){
    auto r=secure_crypto::rand_uint64();
    EXPECT_EQ(sizeof(r),8);
}

TEST(SecureRandomTest, TooLargeRequestThrows) {
    EXPECT_THROW(
        secure_crypto::random_bytes(static_cast<std::size_t>(3) * 1024 * 1024 * 1024),
        std::invalid_argument
    );
}