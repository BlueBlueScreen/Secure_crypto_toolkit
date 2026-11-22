find_package(GTest REQUIRED)

add_executable(crypto_test
    test_aes_gcm.cpp
    test_x25519.cpp
    test_ed25519.cpp
    test_hkdf.cpp
    test_secure_hash.cpp
    test_secure_random.cpp
    test_utils.cpp
)

# GTest::gtest_main 提供 main()，无需自写
target_link_libraries(crypto_test
    PRIVATE
        secure_crypto_toolkit
        GTest::gtest
        GTest::gtest_main
)

# 注册到 CTest，支持 build 目录里直接 ctest
add_test(NAME crypto_test COMMAND crypto_test)
