#pragma once
#include<vector>
#include<cstddef>
#include<cstdint>
using namespace std;

namespace secure_crypto{

//生成指定长随机数
vector<uint8_t> random_bytes(size_t n);
//生成32bit长随机数
uint32_t rand_uint32();
//生成64bit长随机数
uint64_t rand_uint64();
//检查状态
bool is_random_available();

}