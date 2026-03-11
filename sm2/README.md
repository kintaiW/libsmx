# sm2

**SM2 椭圆曲线公钥密码算法** — 纯 Rust、`no_std`、常量时间实现，符合 GB/T 32918-2016。

**SM2 Elliptic Curve Public-Key Cryptography** — Pure-Rust, `no_std`, constant-time implementation conforming to GB/T 32918-2016.

[![Crates.io](https://img.shields.io/crates/v/sm2.svg)](https://crates.io/crates/sm2)
[![Docs.rs](https://docs.rs/sm2/badge.svg)](https://docs.rs/sm2)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../LICENSE)

---

## 目录 / Table of Contents

- [功能 / Features](#功能--features)
- [快速开始 / Quick Start](#快速开始--quick-start)
- [API 概览 / API Overview](#api-概览--api-overview)
- [安全性 / Security](#安全性--security)
- [Feature 标志 / Feature Flags](#feature-标志--feature-flags)
- [依赖 / Dependencies](#依赖--dependencies)

---

## 功能 / Features

**中文：** 本 crate 实现以下 GB/T 32918-2016 标准算法：

**English:** This crate implements the following GB/T 32918-2016 standard algorithms:

| 功能 / Feature | 函数/类型 / Function / Type | 标准 / Standard |
|---|---|---|
| 密钥生成 / Key Generation | `generate_keypair` | GB/T 32918.1 §6.1 |
| 数字签名 / Digital Signature | `sign`, `sign_message`, `SigningKey` | GB/T 32918.2 §6.2 |
| 签名验证 / Verification | `verify`, `verify_message`, `VerifyingKey` | GB/T 32918.2 §6.3 |
| 公钥加密 / Encryption | `encrypt` | GB/T 32918.4 §7.1 |
| 公钥解密 / Decryption | `decrypt` | GB/T 32918.4 §7.2 |
| 密钥交换 / Key Exchange | `key_exchange::ecdh`, `exchange_a/b` | GB/T 32918.3 |
| DER 编解码 / DER Encoding | `der::sig_to_der`, `private_key_from_pkcs8_der` | RFC 5915/5480 |

---

## 快速开始 / Quick Start

在 `Cargo.toml` 中添加 / Add to your `Cargo.toml`:

```toml
[dependencies]
sm2 = { path = "path/to/sm2" }
# 或 crates.io 发布后 / or after crates.io release:
# sm2 = "0.1"
```

### 签名与验签 / Sign and Verify

```rust
use sm2::{SigningKey, VerifyingKey, DEFAULT_ID, generate_keypair};
use sm2::signature::{Signer, Verifier};
use rand_core::OsRng;

// 生成密钥对 / Generate key pair
let (private_key, public_key_bytes) = generate_keypair(&mut OsRng);

// 创建签名/验证密钥 / Create signing and verifying keys
let signing_key   = SigningKey::new(private_key, DEFAULT_ID);
let verifying_key = VerifyingKey::new(public_key_bytes, DEFAULT_ID);

// 签名 / Sign
let message = b"Hello, SM2!";
let signature = signing_key.sign(message);

// 验签 / Verify
verifying_key.verify(message, &signature).expect("验签应通过 / verification should pass");
```

### 底层签名 API / Low-level Signing API

```rust
use sm2::{PrivateKey, generate_keypair, get_z, get_e, sign, verify, DEFAULT_ID};
use rand_core::OsRng;

let (pri_key, pub_key) = generate_keypair(&mut OsRng);

// 计算 Z 值和摘要 / Compute Z-value and digest
let z = get_z(DEFAULT_ID, &pub_key);
let e = get_e(&z, b"my message");

// 签名 / Sign
let sig = sign(&e, &pri_key, &mut OsRng);

// 验签 / Verify
verify(&e, &pub_key, &sig).expect("ok");
```

### 公钥加解密 / Public-key Encrypt / Decrypt

```rust
# #[cfg(feature = "alloc")]
use sm2::{encrypt, decrypt, generate_keypair};
use rand_core::OsRng;

let (pri_key, pub_key) = generate_keypair(&mut OsRng);
let plaintext = b"secret message";

let ciphertext = encrypt(&pub_key, plaintext, &mut OsRng).unwrap();
let recovered  = decrypt(&pri_key, &ciphertext).unwrap();
assert_eq!(recovered, plaintext);
```

密文格式为 `C1 || C3 || C2`（65 + 32 + n 字节），符合 GB/T 32918.4 §6.1。

Ciphertext format: `C1 || C3 || C2` (65 + 32 + n bytes), per GB/T 32918.4 §6.1.

### SM2-ECDH 密钥交换 / Key Exchange

```rust
use sm2::{generate_keypair, key_exchange::ecdh};
use rand_core::OsRng;

let (pri_a, pub_a) = generate_keypair(&mut OsRng);
let (pri_b, pub_b) = generate_keypair(&mut OsRng);

// 双方各自计算，结果一致 / Both parties compute the same shared secret
let shared_a = ecdh(&pri_a, &pub_b).unwrap();
let shared_b = ecdh(&pri_b, &pub_a).unwrap();
assert_eq!(shared_a, shared_b);
```

---

## API 概览 / API Overview

### 类型 / Types

| 类型 / Type | 说明 / Description |
|---|---|
| `PrivateKey` | SM2 私钥（32 字节，离开作用域自动清零）/ SM2 private key (auto-zeroized on drop) |
| `SigningKey<'id>` | 签名密钥（私钥 + 用户 ID）/ Signing key (private key + user ID) |
| `VerifyingKey<'id>` | 验证密钥（公钥 + 用户 ID）/ Verifying key (public key + user ID) |
| `Sm2Signature` | 签名结果（r\|\|s，64 字节）/ Signature (r\|\|s, 64 bytes) |
| `key_exchange::EphemeralKey` | 密钥交换临时密钥对 / Ephemeral key pair for key exchange |
| `Error` | 统一错误类型 / Unified error type |

### 常量 / Constants

| 常量 / Constant | 值 / Value | 说明 / Description |
|---|---|---|
| `DEFAULT_ID` | `b"1234567812345678"` | GB/T 32918.2 §A.2 示例用户 ID / Example user ID from spec |

### 关键函数 / Key Functions

```
generate_keypair(rng)         → (PrivateKey, [u8; 65])
get_z(id, pub_key)            → [u8; 32]
get_e(z, msg)                 → [u8; 32]
sign(e, pri_key, rng)         → [u8; 64]
sign_message(msg, id, pri, rng) → [u8; 64]
verify(e, pub_key, sig)       → Result<(), Error>
verify_message(msg, id, pub, sig) → Result<(), Error>
encrypt(pub_key, msg, rng)    → Result<Vec<u8>, Error>   // alloc
decrypt(pri_key, ciphertext)  → Result<Vec<u8>, Error>   // alloc
```

---

## 安全性 / Security

**中文：**

- **常量时间**：所有私钥相关运算均为常量时间（Montgomery 域算术 + `subtle::ConditionallySelectable`）
- **标量乘法**：固定迭代 256 位，不跳过前导零，防止时序侧信道
- **自动清零**：`PrivateKey` 离开作用域后自动清零（[`ZeroizeOnDrop`]）
- **无 unsafe**：全 crate 使用 `#![forbid(unsafe_code)]`
- **SM4 S-box**：（通过 `sm4` 依赖）使用布尔电路位切片实现，无查表

**English:**

- **Constant-time**: All secret-dependent operations use Montgomery-domain arithmetic + `subtle::ConditionallySelectable`
- **Scalar multiplication**: Iterates all 256 bits regardless of leading zeros — no timing leakage
- **Auto-zeroize**: `PrivateKey` is automatically cleared on drop via [`ZeroizeOnDrop`]
- **No unsafe code**: The entire crate is `#![forbid(unsafe_code)]`
- **Bitslice S-box**: (via `sm4` dependency) uses boolean-circuit implementation, no table lookups

> **危险 API / Dangerous API**: `sign_with_k` 仅在启用 `hazmat` feature 时可用，用于测试向量验证。误用相同 k 值会泄露私钥。
>
> `sign_with_k` is only available with the `hazmat` feature, intended for test-vector validation only. Reusing k across signatures leaks the private key.

---

## Feature 标志 / Feature Flags

| Feature | 默认启用 / Default | 说明 / Description |
|---|---|---|
| `alloc` | ✅ | 启用 `encrypt`/`decrypt` 和 DER 编码（需要 `Vec`）/ Enables `encrypt`/`decrypt` and DER encoding (requires `Vec`) |
| `hazmat` | ❌ | 暴露 `sign_with_k`（危险的固定 k 签名，仅用于测试）/ Exposes `sign_with_k` (dangerous fixed-k signing, test only) |

---

## 依赖 / Dependencies

| Crate | 版本 / Version | 用途 / Purpose |
|---|---|---|
| `sm3` | workspace | SM3 哈希（Z 值、消息摘要、KDF）/ SM3 hash (Z-value, digest, KDF) |
| `crypto-bigint` | 0.6 | 常量时间大整数（Montgomery 域）/ Constant-time big integers |
| `subtle` | 2.6 | 常量时间比较 / Constant-time comparisons |
| `zeroize` | 1.8 | 密钥安全清零 / Secure key zeroization |
| `rand_core` | 0.6 | RNG trait（含 OsRng）/ RNG traits (including OsRng) |
| `signature` | 2.2 | `Signer`/`Verifier` trait 集成 / `Signer`/`Verifier` trait integration |

---

## 许可证 / License

Apache-2.0 — 见 / see [`LICENSE`](../LICENSE)

---

## 参考标准 / Reference Standards

- GB/T 32918.1-2016：SM2 公钥密码算法 第1部分：总则
- GB/T 32918.2-2016：SM2 公钥密码算法 第2部分：数字签名算法
- GB/T 32918.3-2016：SM2 公钥密码算法 第3部分：密钥交换协议
- GB/T 32918.4-2016：SM2 公钥密码算法 第4部分：公钥加密算法
- GB/T 32918.5-2017：SM2 公钥密码算法 第5部分：参数定义
