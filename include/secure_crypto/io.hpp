#pragma once
#include <openssl/evp.h>   // EVP_PKEY
#include <openssl/pem.h>   // PEM 读写
#include <openssl/bio.h>   // BIO 文件/内存抽象
#include <cstdint>
#include <string>
#include <vector>

namespace secure_crypto {

// 从 PEM 文件加载私钥，返回 DER 编码字节串
// 只接受本库支持的密钥算法（X25519 / Ed25519），其他算法（RSA、DSA 等遗留算法）直接拒绝
[[nodiscard]] std::vector<uint8_t> load_private_key_der_from_pem(const std::string& filepath);

// 从 PEM 文件加载公钥（也接受含公钥部分的私钥文件），返回 DER 编码字节串
// 同样只接受 X25519 / Ed25519
[[nodiscard]] std::vector<uint8_t> load_public_key_der_from_pem(const std::string& filepath);

// 读取任意文件为原始字节
[[nodiscard]] std::vector<uint8_t> load_file_as_bytes(const std::string& filepath);

// 将 DER 编码的私钥/公钥写为 PEM 文件（写之前同样检查密钥算法白名单）
void write_private_key_pem(const std::vector<uint8_t>& der_privkey, const std::string& filepath);
void write_public_key_pem(const std::vector<uint8_t>& der_pubkey, const std::string& filepath);

// 直接把内存中的 EVP_PKEY 写成 PEM 文件（供密钥生成函数内部使用）
void write_private_key(EVP_PKEY* pkey, const std::string& filepath);
void write_public_key(EVP_PKEY* pkey, const std::string& filepath);

// 将任意字节写入文件（输出 DER、密文、共享密钥等）
void write_bytes_to_file(const std::vector<uint8_t>& data, const std::string& filepath);

}
