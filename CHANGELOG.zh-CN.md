# 变更日志

本文件记录项目的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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

[0.1.1]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.1
[0.1.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.0
