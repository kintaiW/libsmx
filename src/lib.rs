//! # libsmx
//!
//! Production-grade implementation of Chinese commercial cryptography standards:
//!
//! - **SM2** — Elliptic Curve Public Key Cryptography (GB/T 32918.1-5)
//! - **SM3** — Cryptographic Hash Algorithm (GB/T 32905)
//! - **SM4** — Block Cipher Algorithm (GB/T 32907)
//! - **SM9** — Identity-Based Cryptographic Algorithm (GB/T 38635.1-2)
//!
//! ## Features
//!
//! - `no_std` compatible (requires `alloc` feature for SM2/SM9 operations)
//! - Constant-time operations via [`subtle`](https://docs.rs/subtle)
//! - Automatic key zeroization via [`zeroize`](https://docs.rs/zeroize)
//! - All implementations validated against official GB/T test vectors
//!
//! ## Quick Start
//!
//! ```rust
//! use libsmx::sm3::Sm3Hasher;
//!
//! let mut h = Sm3Hasher::new();
//! h.update(b"hello world");
//! let digest = h.finalize();
//! assert_eq!(digest.len(), 32);
//! ```
//!
//! ## Security Notice
//!
//! This library uses constant-time operations throughout to prevent timing
//! side-channel attacks. Private keys are zeroized on drop. However, this
//! library has **not** been independently audited. Use in production at your
//! own risk.
//!
//! ## Standards Compliance
//!
//! | Algorithm | Standard |
//! |-----------|----------|
//! | SM2 | GB/T 32918.1-5-2016 |
//! | SM3 | GB/T 32905-2016 |
//! | SM4 | GB/T 32907-2016 |
//! | SM9 | GB/T 38635.1-2-2020 |

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// 把 `subtle::Choice` 转成 crypto-bigint 0.7 常量时间 trait 用的 `Choice`。
///
/// Reason: 0.7 起 `ct_select`/`ct_gt`/`ct_lt` 改用 ctutils 的 `Choice`，
///   与本项目其余部分使用的 `subtle` 不是同一个类型。
#[inline]
pub(crate) fn subtle_choice(choice: subtle::Choice) -> crypto_bigint::Choice {
    crypto_bigint::Choice::from_u8_lsb(choice.unwrap_u8())
}

pub mod error;
pub mod sm2;
pub mod sm3;
pub mod sm4;
pub mod sm9;

#[cfg(feature = "alloc")]
pub mod bls;

pub mod fpe;

#[cfg(feature = "rustls-provider")]
pub mod rustls_provider;
