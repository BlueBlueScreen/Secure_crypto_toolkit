#查找GTest库
find_package(GTest REQUIRED)

#创建测试目标
add_executable(CryptoTest
    main.cpp
    test_aes_gcm.cpp
    test_ecdh.cpp
    test_ed25519.cpp
    test_hkdf.cpp
)

#链接库到测试目标
target_link_libraries(CryptoTest PRIVATE Toolkit GTest::Test GTest::Main)

#启动ctest支持
enable_testing()
add_test(NAME CryptoTest COMMAND CryptoTest)