//! SM4 分组密码（GB/T 32907-2016）
//!
//! 提供核心块加密功能。工作模式（CBC/CTR/GCM 等）请使用 RustCrypto 生态的
//! `cbc`、`ctr`、`aes-gcm` 等 crate 与 [`Sm4Key`] 组合使用。

pub(crate) mod cipher;

pub use cipher::Sm4Key;
