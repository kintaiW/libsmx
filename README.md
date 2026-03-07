# libsmx

生产级中国商用密码算法库，纯 Rust 实现。

## 算法支持

| 算法 | 标准 | 功能 |
|------|------|------|
| SM2 | GB/T 32918.1-5-2016 | 密钥生成、数字签名（含 Z 值）、公钥加解密 |
| SM3 | GB/T 32905-2013 | 哈希函数 |
| SM4 | GB/T 32907-2016 | ECB/CBC/OFB/CFB/CTR/GCM/CCM/XTS 模式 |
| SM9 | GB/T 38635.1-2-2020 | BN256 配对密码，签名、加密 |

## 特性

- **常量时间**：使用 `crypto-bigint::ConstMontyForm` 和 `subtle::ConstantTimeEq`
- **内存安全**：私钥通过 `zeroize::ZeroizeOnDrop` 在 Drop 时自动清零
- **no_std 兼容**：默认启用 `alloc` feature，核心算法支持裸机环境
- **零 unsafe**（除 crypto-bigint 内部）

## 快速开始

```toml
[dependencies]
libsmx = "0.1"
```

### SM3 哈希

```rust
use libsmx::sm3::Sm3Hasher;

let mut h = Sm3Hasher::new();
h.update(b"hello");
let digest = h.finalize(); // [u8; 32]
```

### SM4-GCM 加密

```rust
use libsmx::sm4::modes::{sm4_encrypt_gcm, sm4_decrypt_gcm};

let key = [0u8; 16];
let nonce = [1u8; 12];
let (ciphertext, tag) = sm4_encrypt_gcm(&key, &nonce, b"aad", b"plaintext");
let plaintext = sm4_decrypt_gcm(&key, &nonce, b"aad", &ciphertext, &tag).unwrap();
```

### SM2 签名

```rust
use libsmx::sm2::{generate_keypair, sign, verify, get_z, get_e};
use rand::rngs::OsRng;

let (priv_key, pub_key) = generate_keypair(&mut OsRng);
let id = b"1234567812345678";
let msg = b"hello sm2";
let z = get_z(id, &pub_key);
let e = get_e(&z, msg);
let sig = sign(&e, &priv_key, &mut OsRng);
verify(&e, &pub_key, &sig).unwrap();
```

### SM9 配对

```rust
use libsmx::sm9::{generate_sign_master_keypair, generate_sign_user_key, sm9_sign, sm9_verify};
use rand::rngs::OsRng;

let (ks, ppub) = generate_sign_master_keypair(&mut OsRng);
let da = generate_sign_user_key(&ks, b"Alice").unwrap();
let (h, s) = sm9_sign(b"message", &da, &ppub, &mut OsRng).unwrap();
sm9_verify(b"message", &h, &s, b"Alice", &ppub).unwrap();
```

## MSRV

Rust 1.72.0

## 许可证

Apache-2.0
