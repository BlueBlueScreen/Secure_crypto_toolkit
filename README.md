# SecureCryptoToolkit

A minimal C++17 toolkit that wraps OpenSSL 3.0+ cryptographic primitives behind a
small, type-safe, **secure-by-default** API for prototyping authenticated key
agreement and other security engineering tasks.

Raw OpenSSL (EVP) is powerful but easy to misuse — legacy algorithms are one
function call away, and buffer/context management is manual. This library keeps
the EVP layer below but exposes only modern primitives with safe defaults, so
protocol prototypes get correct behavior "for free".

## Supported primitives

| Module | Algorithm | Header |
|---|---|---|
| Authenticated encryption | AES-128/256-GCM | `secure_crypto/aes_gcm.hpp` |
| Key agreement | X25519 (Curve25519 ECDH) | `secure_crypto/x25519.hpp` |
| Signatures | Ed25519 | `secure_crypto/ed25519.hpp` |
| KDF | HKDF-SHA256 (RFC 5869) | `secure_crypto/hkdf.hpp` |
| Hash | SHA-2 (256/384/512), SHA-3 (256/384/512) | `secure_crypto/secure_hash.hpp` |
| CSPRNG | `RAND_bytes` wrapper | `secure_crypto/secure_random.hpp` |
| Utilities | base64 / hex, constant-time compare | `secure_crypto/utils.hpp` |
| Key I/O | PEM ↔ DER, algorithm allowlist | `secure_crypto/io.hpp` |

## Security defaults & disabled legacy surface

Choices the API makes *for* you, so they cannot be gotten wrong at call sites:

- **Weak/legacy algorithms are not exposed.** No MD5, no SHA-1, no CBC mode,
  no RSA PKCS#1 v1.5. Key-loading functions reject any key that is not
  X25519/Ed25519, so legacy PEM files dropped into the app fail fast.
- **AES-GCM nonce is a 96-bit CSPRNG value generated inside the library** —
  callers never supply it and cannot accidentally reuse it. 128-bit auth tag
  is always verified on decrypt; tampering raises `std::runtime_error`.
- **Key length is validated**: AES-GCM accepts only 16- or 32-byte keys.
- **`const_time_compare()`** is provided for MAC/tag comparison to resist
  timing side channels.
- All OpenSSL contexts are released on every path (success and exception);
  `[[nodiscard]]` on value-returning APIs prevents silently dropping results
  such as verification outcomes.

## Requirements

- OpenSSL **>= 3.0** (uses the 3.x `EVP_KDF` framework)
- CMake >= 3.16, a C++17 compiler
- GoogleTest (only to build tests)

## Build & test

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure   # unit tests
./build/benchmarks/bench                     # benchmarks
```

## Quickstart: an authenticated key-agreement prototype

X25519 for key agreement → HKDF to derive a uniform session key →
AES-GCM for authenticated encryption → Ed25519 to sign the transcript:

```cpp
#include <secure_crypto/x25519.hpp>
#include <secure_crypto/hkdf.hpp>
#include <secure_crypto/aes_gcm.hpp>
#include <secure_crypto/ed25519.hpp>
using namespace secure_crypto;

// 1. long-term agreement keys (PEM files)
x25519_keygen("alice_sk.pem", "alice_pk.pem");
x25519_keygen("bob_sk.pem",   "bob_pk.pem");

// 2. ECDH shared secret -> HKDF-SHA256 -> 256-bit session key
auto shared = x25519_derive("alice_sk.pem", "bob_pk.pem");
std::vector<uint8_t> info = {'c','h','a','n','n','e','l','-','0'};
auto session_key = hkdf_sha256(shared, 32, /*salt=*/{}, info);

// 3. authenticated encryption (nonce & tag handled by the library)
std::vector<uint8_t> msg = {'h','e','l','l','o'};
GcmCiphertext ct = aes_gcm_encrypt(session_key, msg, /*aad=*/info);
auto plaintext   = aes_gcm_decrypt(session_key, ct, info);

// 4. sign the transcript
ed25519_keygen("alice_sign_sk.pem", "alice_sign_pk.pem");
auto sig = ed25519_sign("alice_sign_sk.pem", ct.ciphertext);
bool ok  = ed25519_verify(sig, "alice_sign_pk.pem", ct.ciphertext);
```

## Correctness: standard test vectors

Unit tests validate implementations against published standard vectors
(SHA-2 against NIST FIPS 180-4 examples, SHA-3 against FIPS 202 examples,
HKDF against RFC 5869 A.1 test cases 1 & 3, Base64 against RFC 4648), plus
round-trip and negative tests (bit-flipped ciphertext/tag/AAD, wrong keys,
truncated key files, non-whitelisted algorithms). AES-GCM/X25519/Ed25519
fixed-input KATs are intentionally *not* part of the public API surface since
the library refuses caller-supplied nonces — see `tests/` for the exact matrix.

## Benchmarks

`bench/` contains simple throughput benchmarks for AES-256-GCM
(encrypt+decrypt at 64 B / 1 KB / 1 MB) and SHA-2/SHA-3 (1 MB buffers).
Example output (WSL2, x86-64, OpenSSL 3.0.2):

```
AES-256-GCM  size=  1048576 B  throughput(enc+dec) = 1884.0 MB/s
SHA-256      size=  1048576 B  throughput        = 4023.1 MB/s
SHA3-256     size=  1048576 B  throughput        =  677.0 MB/s
```

## Project layout

```
include/secure_crypto/   public headers (the whole API surface)
src/                     OpenSSL EVP wrappers
tests/                   GoogleTest unit tests (standard vectors + negative cases)
benchmarks/              throughput benchmarks
```

## Notes & limitations

- Key material lives in PEM files; file permissions are the deployment's job.
  This is a prototyping toolkit, not an HSM-backed keystore.
- The X25519 output is the raw ECDH secret; always run it through HKDF before
  using it as a key (as in the quickstart above).

## License

MIT
