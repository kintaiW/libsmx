//! 统一错误类型
//!
//! 所有 libsmx 操作均通过此模块中的 [`Error`] 类型报告错误，
//! 兼容 `no_std` 环境（不依赖 `std::error::Error` trait）。

use core::fmt;

/// libsmx 统一错误类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // ── SM2 错误 ────────────────────────────────────────────────────────────
    /// 私钥不在合法范围 [1, n-2]
    InvalidPrivateKey,
    /// 公钥不在椭圆曲线上或格式错误
    InvalidPublicKey,
    /// 签名值 (r, s) 格式或范围不合法
    InvalidSignature,
    /// 签名验证失败（r_check ≠ r）
    VerifyFailed,
    /// 解密失败（MAC/C3 验证不通过或密文格式错误）
    DecryptFailed,
    /// 点在无穷远处（密钥交换中的退化情况）
    PointAtInfinity,
    /// 输入数据长度不合法
    InvalidInputLength,

    // ── SM4 错误 ────────────────────────────────────────────────────────────
    /// AEAD 认证标签验证失败（GCM/CCM 解密时）
    AuthTagMismatch,

    // ── SM9 错误 ────────────────────────────────────────────────────────────
    /// 输入点不在曲线上
    NotOnCurve,
    /// 标量或私钥为零
    ZeroScalar,
    /// 输入整数超出域范围
    IntegerOutOfRange,
    /// SM9 解密验证失败
    Sm9DecryptFailed,
    /// SM9 签名验证失败
    Sm9VerifyFailed,

    // ── 通用错误 ────────────────────────────────────────────────────────────
    /// 输入数据格式无效
    InvalidInput,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPrivateKey => write!(f, "invalid private key"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::VerifyFailed => write!(f, "signature verification failed"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::PointAtInfinity => write!(f, "point at infinity"),
            Error::InvalidInputLength => write!(f, "invalid input length"),
            Error::AuthTagMismatch => write!(f, "authentication tag mismatch"),
            Error::NotOnCurve => write!(f, "point not on curve"),
            Error::ZeroScalar => write!(f, "zero scalar"),
            Error::IntegerOutOfRange => write!(f, "integer out of range"),
            Error::Sm9DecryptFailed => write!(f, "SM9 decryption failed"),
            Error::Sm9VerifyFailed => write!(f, "SM9 signature verification failed"),
            Error::InvalidInput => write!(f, "invalid input"),
        }
    }
}

// Reason: std::error::Error 只在 std 环境可用；no_std 环境下仅提供 Display + Debug。
//   条件编译确保 alloc-only 场景不引入 std 依赖。
#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// libsmx 统一 Result 类型
pub type Result<T> = core::result::Result<T, Error>;
