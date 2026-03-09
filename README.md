# libsmx

[![CI](https://github.com/kintaiW/libsmx/actions/workflows/ci.yml/badge.svg)](https://github.com/kintaiW/libsmx/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/libsmx.svg)](https://crates.io/crates/libsmx)
[![docs.rs](https://img.shields.io/docsrs/libsmx)](https://docs.rs/libsmx)
[![codecov](https://codecov.io/gh/kintaiW/libsmx/graph/badge.svg)](https://codecov.io/gh/kintaiW/libsmx)
[![License](https://img.shields.io/crates/l/libsmx.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.83.0-blue.svg)](https://blog.rust-lang.org/2024/11/28/Rust-1.83.0.html)

Pure-Rust, `#![no_std]` implementation of Chinese commercial cryptography standards with constant-time operations throughout.

| Algorithm | Standard | Description |
|-----------|----------|-------------|
| **SM2** | GB/T 32918.1-5-2016 | Elliptic Curve Public Key Cryptography |
| **SM3** | GB/T 32905-2016 | Cryptographic Hash Algorithm (256-bit) |
| **SM4** | GB/T 32907-2016 | Block Cipher (128-bit key, ECB/CBC/CTR/GCM/CCM/XTS) |
| **SM9** | GB/T 38635.1-2-2020 | Identity-Based Cryptography (BN256 pairing) |
| **BLS** | IETF RFC 9380 | BLS Signatures & Threshold Signatures (BN256) |
| **FPE** | NIST SP 800-38G | Format-Preserving Encryption (FF1-like) |

## Features

- **`#![no_std]`** — works in embedded, WASM, and bare-metal environments
- **`#![forbid(unsafe_code)]`** — zero `unsafe` blocks
- **Constant-time** — all secret-dependent operations use [`subtle`](https://docs.rs/subtle) primitives
- **Auto-zeroize** — private keys cleared on drop via [`zeroize`](https://docs.rs/zeroize)
- **Side-channel resistant SM4 S-box** — boolean circuit bitslice (no table lookup)
- **Complete EC formulas** — SM2 point addition uses branch-free complete formulas

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
libsmx = "0.3"
```

### SM3 Hash

```rust
use libsmx::sm3::Sm3Hasher;

// One-shot hash
let digest = Sm3Hasher::digest(b"abc");
assert_eq!(digest.len(), 32);

// Streaming hash
let mut h = Sm3Hasher::new();
h.update(b"ab");
h.update(b"c");
assert_eq!(h.finalize(), digest);
```

### SM3 HMAC

```rust
use libsmx::sm3::hmac_sm3;

let mac = hmac_sm3(b"secret-key", b"message");
assert_eq!(mac.len(), 32);
```

### SM2 Sign / Verify

```rust
use libsmx::sm2::{generate_keypair, get_z, get_e, sign, verify};

let mut rng = rand::rngs::OsRng;

// Key generation
let (pri_key, pub_key) = generate_keypair(&mut rng);

// Sign: compute Z value and message digest per GB/T 32918.2
let z = get_z(b"1234567812345678", &pub_key);
let e = get_e(&z, b"hello SM2");
let sig = sign(&e, &pri_key, &mut rng);

// Verify
verify(&e, &pub_key, &sig).expect("signature valid");
```

### SM4 GCM (AEAD)

```rust
use libsmx::sm4::{sm4_encrypt_gcm, sm4_decrypt_gcm};

let key = [0u8; 16];
let nonce = [0u8; 12];
let aad = b"additional data";
let plaintext = b"secret message";

let (ciphertext, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plaintext);
let decrypted = sm4_decrypt_gcm(&key, &nonce, aad, &ciphertext, &tag).unwrap();
assert_eq!(decrypted, plaintext);
```

### SM4 CBC

```rust
use libsmx::sm4::{sm4_encrypt_cbc, sm4_decrypt_cbc};

let key = [0u8; 16];
let iv = [0u8; 16];
let plaintext = [0u8; 32]; // must be 16-byte aligned

let ciphertext = sm4_encrypt_cbc(&key, &iv, &plaintext);
let decrypted = sm4_decrypt_cbc(&key, &iv, &ciphertext);
assert_eq!(decrypted, plaintext);
```

### SM9 Identity-Based Sign / Verify

```rust
use libsmx::sm9::{generate_sign_master_keypair, generate_sign_user_key};
use libsmx::sm9::{sm9_sign, sm9_verify};

let mut rng = rand::rngs::OsRng;

// KGC generates master keypair
let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);

// KGC generates user signing key for identity
let user_id = b"alice@example.com";
let user_key = generate_sign_user_key(&master_priv, user_id).unwrap();

// User signs message
let msg = b"hello SM9";
let (h, s) = sm9_sign(msg, &user_key, &sign_pub, &mut rng).unwrap();

// Anyone can verify with user's identity + master public key
sm9_verify(msg, &h, &s, user_id, &sign_pub).unwrap();
```

## Supported SM4 Modes

| Mode | Encrypt | Decrypt |
|------|---------|---------|
| ECB | `sm4_encrypt_ecb` | `sm4_decrypt_ecb` |
| CBC | `sm4_encrypt_cbc` | `sm4_decrypt_cbc` |
| OFB | `sm4_crypt_ofb` | `sm4_crypt_ofb` |
| CFB | `sm4_encrypt_cfb` | `sm4_decrypt_cfb` |
| CTR | `sm4_crypt_ctr` | `sm4_crypt_ctr` |
| GCM | `sm4_encrypt_gcm` | `sm4_decrypt_gcm` |
| CCM | `sm4_encrypt_ccm` | `sm4_decrypt_ccm` |
| XTS | `sm4_encrypt_xts` | `sm4_decrypt_xts` |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `alloc` | Yes | Enables `Vec`-returning APIs (SM2/SM9 encrypt/decrypt, SM4 modes) |
| `std` | No | Enables `std::error::Error` impl and re-exports `rand_core/std` |

For `no_std` without `alloc`:

```toml
[dependencies]
libsmx = { version = "0.3", default-features = false }
```

## Benchmarks

Measured on Linux x86_64 (single core). All operations are constant-time.

### Throughput

| Algorithm | Data Size | Time | Throughput |
|-----------|-----------|------|------------|
| SM3 hash | 64 B | 349 ns | — |
| SM3 hash | 1 KiB | 2.80 µs | — |
| SM3 hash | 64 KiB | 167 µs | **374 MiB/s** |
| SM4-ECB encrypt | 16 B | 1.14 µs | — |
| SM4-ECB encrypt | 1 KiB | 37.0 µs | — |
| SM4-ECB encrypt | 64 KiB | 2.32 ms | **27 MiB/s** |

### SM2 (256-bit ECC)

| Operation | Time |
|-----------|------|
| Key generation | 221 µs |
| Sign | 258 µs |
| Verify | 316 µs |
| Encrypt | 639 µs |
| Decrypt | 417 µs |

### SM9 (BN256 pairing-based)

| Operation | Time |
|-----------|------|
| Master keygen | 753 µs |
| User keygen | 324 µs |
| Sign | 3.44 ms |
| Verify | 5.50 ms |
| Encrypt | 4.68 ms |
| Decrypt | 1.54 ms |

Run benchmarks locally:

```bash
cargo bench
```

## Security

- All secret-dependent operations are constant-time (fixed iteration counts, mask-based selection)
- SM4 S-box uses boolean circuit bitslice — zero memory access patterns, immune to cache-timing attacks
- SM2 scalar multiplication uses complete addition formulas with no data-dependent branches
- Private keys implement `ZeroizeOnDrop` for automatic cleanup
- GCM/CCM authentication tags are verified in constant time

> **Disclaimer**: This library has **not** been independently audited. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## MSRV Policy

The minimum supported Rust version is **1.83.0**. MSRV bumps are treated as minor version changes.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
