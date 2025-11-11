#pragma once
#include <openssl/types.h>
#include<vector>
#include<cstddef>
#include<cstdint>
#include<openssl/evp.h>
#include<stdexcept>
using namespace std;
namespace secure_crypto{
        vector<uint8_t> hkdf_sha256(
        const vector<uint8_t>& ikm,
        size_t n,
        const vector<uint8_t>& salt={},
        const vector<uint8_t>& info={}
    );
}