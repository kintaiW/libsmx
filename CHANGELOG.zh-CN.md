# 变更日志

本文件记录项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.0] - 2025-03-09

### 新增

- **rustls CryptoProvider**（`rustls_provider` 模块，需 `rustls` 特性）
  - 完整的 rustls 0.23.x `CryptoProvider` 实现，支持 TLCP（国密 TLS）
  - `hash.rs`：SM3 `Hash` 和 `Context` trait 实现
  - `hmac.rs`：SM3 HMAC trait 实现
  - `tls13.rs`：SM4-GCM/CCM AEAD 密码套件（TLS13_SM4_GCM_SM3、TLS13_SM4_CCM_SM3）
  - `kx.rs`：SM2 ECDHE 密钥交换
  - `sign.rs`：SM2 签名算法
  - `verify.rs`：SM2 验签算法
  - `mod.rs`：`crypto_provider()` 函数返回完整 `CryptoProvider`
- **SM3 流式 HMAC**（`HmacSm3`）
  - `update()`：流式数据输入
  - `finalize()`：最终 HMAC 计算
- **SM2 SPKI DER 编码**
  - `public_key_to_spki_der()`：将公钥编码为 RFC 5480 SubjectPublicKeyInfo
- **SM2 DEFAULT_ID 常量**
  - `DEFAULT_ID`：默认用户 ID "1234567812345678"（16 字节）

### 变更

- `Cargo.toml`：添加 `rustls` 可选特性及依赖

## [0.2.1] - 2025-03-08

### 新增

- **SM2 密钥交换**（`sm2::key_exchange` 模块）
  - `exchange_a` / `exchange_b`：GB/T 32918.3 完整密钥交换协议（带确认哈希）
  - `ecdh`：简单 SM2-ECDH 共享密钥计算（适配 TLS/rustls）
  - `EphemeralKey`：临时密钥对（`ZeroizeOnDrop`）
- **SM2 DER 编解码**（`sm2::der` 模块）
  - `sig_to_der` / `sig_from_der`：签名 DER 编解码
  - `private_key_from_sec1_der` / `private_key_from_pkcs8_der`：私钥解析
- **SM2 便捷 API**（`sm2` 模块）
  - `sign_message` / `verify_message`：自动计算 Z 值的一步签名/验签
- **HKDF-SM3**（`sm3::hkdf` 模块）
  - `hkdf_extract` / `hkdf_expand` / `hkdf`：RFC 5869 兼容
- **SM3 Hasher 增强**
  - `reset()` / `finalize_reset()`：支持流式复用
- **SM4 AEAD 合并格式**
  - `sm4_encrypt_gcm_combined` / `sm4_decrypt_gcm_combined`：TLS 格式（密文||Tag）
  - `sm4_encrypt_ccm_combined` / `sm4_decrypt_ccm_combined`：同上
- **BLS 签名**（`bls` 模块，需 `alloc` 特性）
  - `bls_keygen` / `bls_sign` / `bls_verify`：最小签名尺寸变体（签名 ∈ G1，公钥 ∈ G2）
  - `bls_aggregate` / `bls_aggregate_verify`：多消息聚合签名
  - `bls_fast_aggregate_verify`：同消息多签名者快速聚合验证
  - `BlsSignature::to_bytes` / `from_bytes`：65 字节序列化（非压缩 G1 点）
  - `BlsPubKey::to_bytes` / `from_bytes`：128 字节序列化（非压缩 G2 点）
- **BLS 门限签名**（`bls::threshold` 模块）
  - `bls_threshold_keygen`：可信分发者模式，Shamir 多项式秘密分享
  - `bls_partial_sign` / `bls_combine_signatures`：Lagrange 插值聚合
  - 支持 (t+1, n) 门限配置
- **Hash-to-Curve**（`bls::hash_to_curve` 模块）
  - `hash_to_g1`：符合 RFC 9380，将任意消息映射到 BN256 G1 点
  - `expand_message_xmd`：RFC 9380 §5.3.1，使用 SM3 进行消息扩展
  - `map_to_curve_svdw`：Shallue-van de Woestijne 映射（BN256 a=0 曲线）
- **`fp_sqrt`** 在 `sm9::fields::fp` 中
  - Tonelli-Shanks 模平方根（SM9 BN256 Fp，p ≡ 1 mod 4）
  - `fp_is_square`：基于欧拉判据的二次剩余判定
- **FPE 格式保留加密**（`fpe` 模块）
  - `FpeKey`：基于 SM4 的 7 轮 Luby-Rackoff Feistel 密码
  - 支持 1~128 位明文/密文域
  - `expand_tweak`：通过 SM4 哈希实现任意长度 tweak
  - 离开作用域自动清零密钥（`ZeroizeOnDrop`）

### 安全

- BLS 签名 DST 分离：签名使用 `BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_`，PoP 使用不同标签
- BN256 安全说明：API 文档中注明约 100 位实际安全强度

## [0.1.1] - 2025-03-07

### 修复

- 修复 `cargo test --no-default-features --lib` 编译错误
  - SM3 测试：移除 alloc 依赖，改用手动十六进制解析
  - SM4 modes 测试：添加 `#[cfg(feature = "alloc")]`

### 变更

- MSRV 提升至 1.83.0（crypto-bigint 0.6.x 的 ConstMontyForm 常量时间 Montgomery 算术所需）
- 使用 Rust 1.83+ 内置 `div_ceil` 方法替代手动实现

### CI

- 优化 sanity_check.sh 跳过测试代码，避免误报

## [0.1.0] - 2025-03-07

### 新增

- SM2 椭圆曲线密码 (GB/T 32918.1-5-2016)
  - 密钥生成、数字签名（含 Z 值）、公钥加解密
  - 常量时间点运算的完整加法公式
  - 固定窗口 (w=4) 基点标量乘法及预计算表
  - 混合 Jacobian-Affine 加法优化验证（Shamir 技巧）
  - 点压缩/解压（GB/T 32918.1 第 4.2.10 节）
- SM3 密码杂凑算法 (GB/T 32905-2016)
  - 流式和一次性哈希 API
  - HMAC-SM3，自动清零密钥材料
- SM4 分组密码 (GB/T 32907-2016)
  - 布尔电路 bitslice S-box（抗缓存时序攻击）
  - 8 种工作模式：ECB、CBC、OFB、CFB、CTR、GCM、CCM、XTS
  - GCM/CCM 认证加密，常量时间标签验证
- SM9 标识密码 (GB/T 38635.1-2-2020)
  - BN256 配对（最优 Ate，Miller 循环 + 最终幂）
  - Fp12 塔式扩张：Fp -> Fp2(u²+2) -> Fp6(v³-u) -> Fp12(w²-v)
  - 标识签名与验证
  - 标识加密与解密
- 统一 `Error` 枚举，实现 `Display` 和条件 `std::error::Error`
- `no_std` 支持，可选 `alloc` 和 `std` 特性
- 库级别强制 `#![forbid(unsafe_code)]`
- 通过 `zeroize::ZeroizeOnDrop` 自动清零私钥
- 所有算法的 GB/T 标准测试向量
- 所有算法的 Criterion 基准测试及性能基线数据：
  - SM3：374 MiB/s 吞吐量（64 KiB）
  - SM4-ECB：27 MiB/s 吞吐量（64 KiB）
  - SM2 签名：258 µs，验签：316 µs
  - SM9 签名：3.44 ms，验签：5.50 ms

### 变更

- MSRV 提升至 1.83.0（crypto-bigint 0.6.x 的 ConstMontyForm 常量时间 Montgomery 算术所需）

### 安全

- GCM `gf128_mul`：用掩码运算替换依赖秘密的 `if` 分支
- SM2 `is_infinity`：用 `ConstantTimeEq` 替换短路 `Iterator::all`
- SM2 `add`：用完整加法公式 + `conditional_select` 替换 3 个条件分支
- SM2 `double`：用 `conditional_select` 替换 `if is_infinity()`
- HMAC-SM3：为栈上的 `k_pad`/`ipad`/`opad` 密钥材料添加 `zeroize`
- CCM：拒绝 AAD > 510 字节，而非静默跳过
- XTS：拒绝非 16 字节对齐输入，而非静默截断
- SM9 `hash_to_range`：用常量时间条件选择替换可变迭代 `while` 循环

[0.3.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.3.0
[0.2.1]: https://github.com/kintaiW/libsmx/releases/tag/v0.2.1
[0.2.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.2.0
[0.1.1]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.1
[0.1.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.0
