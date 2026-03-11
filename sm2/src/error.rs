//! SM2 错误类型
//!
//! SM2 Error types used by all public APIs.

use core::fmt;

/// SM2 操作的统一错误类型
///
/// Unified error type for all SM2 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// 私钥不合法（d ∉ [1, n-2]）/ Invalid private key (d ∉ [1, n-2])
    InvalidPrivateKey,
    /// 公钥不合法（格式错误或不在曲线上）/ Invalid public key (bad format or not on curve)
    InvalidPublicKey,
    /// 签名格式不合法 / Invalid signature format
    InvalidSignature,
    /// 验签失败 / Signature verification failed
    VerifyFailed,
    /// 解密失败（C3 校验不通过）/ Decryption failed (C3 check failed)
    DecryptFailed,
    /// 点在无穷远处 / Point at infinity
    PointAtInfinity,
    /// 输入长度不合法 / Invalid input length
    InvalidInputLength,
    /// 密钥交换失败 / Key exchange failed
    KeyExchangeFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPrivateKey  => f.write_str("SM2: invalid private key"),
            Error::InvalidPublicKey   => f.write_str("SM2: invalid public key"),
            Error::InvalidSignature   => f.write_str("SM2: invalid signature format"),
            Error::VerifyFailed       => f.write_str("SM2: signature verification failed"),
            Error::DecryptFailed      => f.write_str("SM2: decryption failed"),
            Error::PointAtInfinity    => f.write_str("SM2: point at infinity"),
            Error::InvalidInputLength => f.write_str("SM2: invalid input length"),
            Error::KeyExchangeFailed  => f.write_str("SM2: key exchange failed"),
        }
    }
}

/// Bridge to `signature::Error` for `Signer`/`Verifier` trait impls.
impl From<Error> for signature::Error {
    fn from(_: Error) -> Self {
        signature::Error::new()
    }
}
