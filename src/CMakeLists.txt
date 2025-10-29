#将源文件打包
set(
    SCT_SRC
    aes_gcm.cpp
    ecdh.cpp
    ed25519.cpp
    hkdf.cpp
    secure_random.cpp
    utils.cpp
)

#将这些源文件编译成库
add_library(Toolkit STATIC ${SCT_SRC})

#公开头文件目录
target_include_directories(Toolkit PUBLIC ${PROJECT_SOURCE_DIR}/include)

#链接 OPENSSL库
target_link_libraries(Toolkit PRIVATE OPENSSL::Crypto)

