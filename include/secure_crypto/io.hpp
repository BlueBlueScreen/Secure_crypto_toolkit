#include <openssl/evp.h>   // EVP_PKEY, PEM_read_bio_PrivateKey, PEM_read_bio_PUBKEY
#include <openssl/pem.h>   // PEM I/O functions (included implicitly by some, but explicitly required)
#include <openssl/bio.h>   // BIO_new_file, BIO_free, BIO_get_mem_data, etc.
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <vector>
using namespace std;


namespace secure_crypto{
// 从 PEM 文件加载私钥（任意算法），返回 DER 编码
vector<uint8_t> load_private_key_der_from_pem(const std::string& filepath);

// 从 PEM 文件加载公钥（任意算法），返回 DER 编码
vector<uint8_t> load_public_key_der_from_pem(const std::string& filepath);

// 读取任意文件为原始字节（用于加载 DER、明文等）
vector<uint8_t> load_file_as_bytes(const std::string& filepath);
// 将 DER 编码的私钥写为 PEM 文件
void write_private_key_pem(const std::vector<uint8_t>& der_privkey, const std::string& filepath);

// 将 DER 编码的公钥写为 PEM 文件
void write_public_key_pem(const std::vector<uint8_t>& der_pubkey, const std::string& filepath);

// 将任意字节写入文件（用于输出 DER、密文、共享密钥等）
void write_bytes_to_file(const std::vector<uint8_t>& data, const std::string& filepath);

}