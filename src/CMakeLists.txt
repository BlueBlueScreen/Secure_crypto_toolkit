add_library(secure_crypto_toolkit
    aes_gcm.cpp
    x25519.cpp
    ed25519.cpp
    hkdf.cpp
    secure_random.cpp
    io.cpp
    utils.cpp
)

# 对外暴露头文件目录
target_include_directories(secure_crypto_toolkit PUBLIC ${PROJECT_SOURCE_DIR}/include)

# 要求 OpenSSL 3.0 及以上（EVP_KDF 等新接口依赖 3.0）
find_package(OpenSSL 3.0 REQUIRED)
target_link_libraries(secure_crypto_toolkit PRIVATE OpenSSL::Crypto)
