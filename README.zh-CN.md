# libsmx

[![CI](https://github.com/kintaiW/libsmx/actions/workflows/ci.yml/badge.svg)](https://github.com/kintaiW/libsmx/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/libsmx.svg)](https://crates.io/crates/libsmx)
[![docs.rs](https://img.shields.io/docsrs/libsmx)](https://docs.rs/libsmx)
[![codecov](https://codecov.io/gh/kintaiW/libsmx/graph/badge.svg)](https://codecov.io/gh/kintaiW/libsmx)
[![License](https://img.shields.io/crates/l/libsmx.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.83.0-blue.svg)](https://blog.rust-lang.org/2024/11/28/Rust-1.83.0.html)

纯 Rust、`#![no_std]` 实现的中国商用密码算法库，全程常量时间操作。

| 算法 | 标准 | 说明 |
|------|------|------|
| **SM2** | GB/T 32918.1-5-2016 | 椭圆曲线公钥密码 |
| **SM3** | GB/T 32905-2016 | 密码杂凑算法（256 位） |
| **SM4** | GB/T 32907-2016 | 分组密码（128 位密钥，ECB/CBC/CTR/GCM/CCM/XTS） |
| **SM9** | GB/T 38635.1-2-2020 | 标识密码（BN256 双线性配对） |

## 特性

- **`#![no_std]`** — 支持嵌入式、WASM 及裸机环境
- **`#![forbid(unsafe_code)]`** — 零 `unsafe` 块
- **常量时间** — 所有涉密操作均使用 [`subtle`](https://docs.rs/subtle) 原语，防时序侧信道
- **自动清零** — 私钥离开作用域后经由 [`zeroize`](https://docs.rs/zeroize) 自动清零
- **SM4 S 盒抗侧信道** — 布尔电路位切片实现，无任何内存表查询，免疫缓存时序攻击
- **SM2 完备加法公式** — 点加法使用无分支完备公式，杜绝特殊情况侧信道

## 快速开始

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
libsmx = "0.1"
```

### SM3 哈希

```rust
use libsmx::sm3::Sm3Hasher;

// 一次性哈希
let digest = Sm3Hasher::digest(b"abc");
assert_eq!(digest.len(), 32);

// 流式哈希
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

### SM2 签名 / 验签

```rust
use libsmx::sm2::{generate_keypair, get_z, get_e, sign, verify};

let mut rng = rand::rngs::OsRng;

// 生成密钥对
let (pri_key, pub_key) = generate_keypair(&mut rng);

// 签名：按 GB/T 32918.2 计算 Z 值与消息摘要
let z = get_z(b"1234567812345678", &pub_key);
let e = get_e(&z, b"hello SM2");
let sig = sign(&e, &pri_key, &mut rng);

// 验签
verify(&e, &pub_key, &sig).expect("签名有效");
```

### SM2 加密 / 解密

```rust
use libsmx::sm2::{generate_keypair, sm2_encrypt, sm2_decrypt};

let mut rng = rand::rngs::OsRng;
let (pri_key, pub_key) = generate_keypair(&mut rng);

let plaintext = b"hello SM2 encrypt";
let ciphertext = sm2_encrypt(&pub_key, plaintext, &mut rng).unwrap();
let decrypted = sm2_decrypt(&pri_key, &ciphertext).unwrap();
assert_eq!(decrypted, plaintext);
```

### SM4-GCM（AEAD 认证加密）

```rust
use libsmx::sm4::{sm4_encrypt_gcm, sm4_decrypt_gcm};

let key   = [0u8; 16];
let nonce = [0u8; 12];
let aad   = b"附加认证数据";
let plaintext = b"机密消息";

let (ciphertext, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plaintext);
let decrypted = sm4_decrypt_gcm(&key, &nonce, aad, &ciphertext, &tag).unwrap();
assert_eq!(decrypted, plaintext);
```

### SM4-CBC

```rust
use libsmx::sm4::{sm4_encrypt_cbc, sm4_decrypt_cbc};

let key = [0u8; 16];
let iv  = [0u8; 16];
let plaintext = [0u8; 32]; // 须为 16 字节对齐

let ciphertext = sm4_encrypt_cbc(&key, &iv, &plaintext);
let decrypted  = sm4_decrypt_cbc(&key, &iv, &ciphertext);
assert_eq!(decrypted, plaintext);
```

### SM9 标识签名 / 验签

```rust
use libsmx::sm9::{generate_sign_master_keypair, generate_sign_user_key};
use libsmx::sm9::{sm9_sign, sm9_verify};

let mut rng = rand::rngs::OsRng;

// 密钥生成中心（KGC）生成主密钥对
let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);

// KGC 为用户标识派生签名私钥
let user_id = b"alice@example.com";
let user_key = generate_sign_user_key(&master_priv, user_id).unwrap();

// 用户签名
let msg = b"hello SM9";
let (h, s) = sm9_sign(msg, &user_key, &sign_pub, &mut rng).unwrap();

// 任意方可凭用户标识 + 主公钥验签
sm9_verify(msg, &h, &s, user_id, &sign_pub).unwrap();
```

### SM9 标识加密 / 解密

```rust
use libsmx::sm9::{generate_enc_master_keypair, generate_enc_user_key};
use libsmx::sm9::{sm9_encrypt, sm9_decrypt};

let mut rng = rand::rngs::OsRng;

let (master_priv, enc_pub) = generate_enc_master_keypair(&mut rng);
let user_id = b"bob@example.com";
let user_key = generate_enc_user_key(&master_priv, user_id).unwrap();

let plaintext = b"机密消息";
let ciphertext = sm9_encrypt(user_id, plaintext, &enc_pub, &mut rng).unwrap();
let decrypted  = sm9_decrypt(user_id, &ciphertext, &user_key).unwrap();
assert_eq!(decrypted, plaintext);
```

## SM4 支持的工作模式

| 模式 | 加密 | 解密 |
|------|------|------|
| ECB | `sm4_encrypt_ecb` | `sm4_decrypt_ecb` |
| CBC | `sm4_encrypt_cbc` | `sm4_decrypt_cbc` |
| OFB | `sm4_crypt_ofb` | `sm4_crypt_ofb` |
| CFB | `sm4_encrypt_cfb` | `sm4_decrypt_cfb` |
| CTR | `sm4_crypt_ctr` | `sm4_crypt_ctr` |
| GCM | `sm4_encrypt_gcm` | `sm4_decrypt_gcm` |
| CCM | `sm4_encrypt_ccm` | `sm4_decrypt_ccm` |
| XTS | `sm4_encrypt_xts` | `sm4_decrypt_xts` |

## Feature 开关

| Feature | 默认启用 | 说明 |
|---------|----------|------|
| `alloc` | 是 | 启用返回 `Vec` 的 API（SM2/SM9 加解密、SM4 各模式） |
| `std`   | 否 | 启用 `std::error::Error` trait 实现及 `rand_core/std` 重导出 |

在无 `alloc` 的 `no_std` 环境中使用：

```toml
[dependencies]
libsmx = { version = "0.1", default-features = false }
```

无 `alloc` 时，SM3 哈希、SM3 HMAC、SM2 签名/验签、SM4 ECB 仍可用（固定大小数组 API）。

## 基准性能

测试环境：Linux x86_64（单核）。所有操作均为常量时间。

### 吞吐量

| 算法 | 数据量 | 耗时 | 吞吐量 |
|------|--------|------|--------|
| SM3 哈希 | 64 B | 349 ns | — |
| SM3 哈希 | 1 KiB | 2.80 µs | — |
| SM3 哈希 | 64 KiB | 167 µs | **374 MiB/s** |
| SM4-ECB 加密 | 16 B | 1.14 µs | — |
| SM4-ECB 加密 | 1 KiB | 37.0 µs | — |
| SM4-ECB 加密 | 64 KiB | 2.32 ms | **27 MiB/s** |

### SM2（256 位椭圆曲线）

| 操作 | 耗时 |
|------|------|
| 密钥生成 | 221 µs |
| 签名 | 258 µs |
| 验签 | 316 µs |
| 加密 | 639 µs |
| 解密 | 417 µs |

### SM9（BN256 双线性配对）

| 操作 | 耗时 |
|------|------|
| 主密钥生成 | 753 µs |
| 用户密钥派生 | 324 µs |
| 签名 | 3.44 ms |
| 验签 | 5.50 ms |
| 加密 | 4.68 ms |
| 解密 | 1.54 ms |

本地运行基准测试：

```bash
cargo bench
```

## 安全性

- 所有涉密操作均为常量时间（固定迭代次数 + 掩码选择，消除数据依赖分支）
- SM4 S 盒采用布尔电路位切片，无任何内存访问模式，免疫缓存时序攻击
- SM2 标量乘法使用 w=4 固定窗口预计算 + 常量时间表查找，消除分支
- SM2 点加法使用完备公式（Renes-Costello-Batina 2016），无退化情况分支
- 私钥类型均实现 `ZeroizeOnDrop`，离开作用域后自动清零内存
- GCM/CCM 认证标签采用常量时间比较，防止 Padding Oracle 攻击

> **免责声明**：本库**尚未**经过独立第三方安全审计。如发现安全漏洞，请参阅 [SECURITY.md](SECURITY.md) 进行报告。

## 最低支持 Rust 版本（MSRV）

最低支持版本为 **Rust 1.83.0**。MSRV 提升视为次版本号变更。

## 许可证

Apache License, Version 2.0。详见 [LICENSE](LICENSE)。
