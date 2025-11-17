# Secure Crypto Toolkit
A modern, secure, and easy-to-use C++17 cryptographic toolkit built on OpenSSL 3.0+. Designed for correctness, safety, and performance—no legacy ciphers allowed.

## Features
- **Authenticated Encryption**: AES-GCM (supports 128bits, 256bits)
- **Elliptic Curve Key Exchange**: ECDH over x25519
- **Digital signature**: Ed25519 (RFC 8032)
- **Cryptographic Primitives**: :
    - HKDF
    - Hash Functions including SHA256, SHA3, MD5 (supports streaming (incremental) hashing)
- **Secure Randomness**: random_bytes(n) using OS CSPRNG (RAND_bytes)
- **Seucrity Hardening**:
    - Constant-time comparison
    - Zero plaintext exposure on decryption failure
- **Validation**: Neccessary function are tested against NIST test vectors.

## Requirements
- C++ 17 compiler
- Openssl 3.0+
- CMAKE 3.18+
- GoogleTest 1.10+

## Quick Start
```
git clone https://github.com/BlueBlueSreen/secure-crypto-toolkit.git
cd secure-crypto-toolkit
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
ctest -V #unit tests
```
## Supplyments
We also performed throughput benchmarks for AES-GCM (skipped the rest out of laziness); you can run your own tests with the following command:
```
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target Bench_mark_test
./benchmarks/Bench_mark_test
```
A example results are as follows:
- Data size:       64 B, Throughput: 75.33 MB/s
- Data size:     1024 B, Throughput: 1062.81 MB/s
- Data size:  1048576 B, Throughput: 905.71 MB/s

Note that our current wrapping principle prioritizes simple interfaces and memory safety. Each call independently initializes its own context to avoid the complexity of state management. This typically caps large-data throughput at ~900 MB/s, which is generally sufficient for protocol prototyping.
