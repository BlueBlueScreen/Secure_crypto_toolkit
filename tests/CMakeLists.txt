# tests/CMakeLists.txt

# 查找 GTest（正确方式）
find_package(GTest REQUIRED)

# 创建测试可执行文件
add_executable(CryptoTest
    test_aes_gcm.cpp
    test_ecdh.cpp
    test_ed25519.cpp
    test_hkdf.cpp
    test_secure_random.cpp
    # 注意：如果你用 GTest::gtest_main，就不需要 main.cpp！
)

# 链接库
target_link_libraries(CryptoTest
    PRIVATE
        Toolkit
        GTest::gtest
        GTest::gtest_main  # 提供 main()，所以不需要你自己的 main.cpp
)

# 注册为 CTest 测试
add_test(NAME CryptoTest COMMAND CryptoTest)