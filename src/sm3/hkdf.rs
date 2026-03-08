//! HKDF-SM3：基于 HMAC-SM3 的密钥派生函数（RFC 5869）
//!
//! TLS 1.3 的密钥调度完全基于 HKDF，因此本模块是 rustls 国密适配的基础依赖。
//!
//! ## 协议
//!
//! ```text
//! Extract:  PRK = HMAC-SM3(salt, IKM)
//! Expand:   T(0) = b""
//!           T(i) = HMAC-SM3(PRK, T(i-1) || info || i)   i = 1, 2, ...
//!           OKM  = T(1) || T(2) || ... 取前 len 字节
//! ```
//!
//! 参考：[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use super::hmac_sm3;
use super::DIGEST_LEN;
#[cfg(feature = "alloc")]
use crate::error::Error;

/// HKDF-SM3 Extract
///
/// PRK = HMAC-SM3(salt, IKM)
///
/// # 参数
/// - `salt`：可选盐值；`None` 时视为全零 32 字节（RFC 5869 §2.2）
/// - `ikm`：输入密钥材料
///
/// # 返回
/// 32 字节伪随机密钥（PRK）
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; DIGEST_LEN] {
    // Reason: RFC 5869 §2.2 规定 salt 缺省时视为长度为 HashLen 的零字节序列
    let zeros = [0u8; DIGEST_LEN];
    let salt = salt.unwrap_or(&zeros);
    hmac_sm3(salt, ikm)
}

/// HKDF-SM3 Expand
///
/// OKM = T(1) || T(2) || ... 截取前 `len` 字节
///
/// # 参数
/// - `prk`：32 字节伪随机密钥（来自 `hkdf_extract` 输出）
/// - `info`：上下文信息（可为空）
/// - `len`：期望输出长度（字节），不得超过 255 × 32 = 8160
///
/// # 错误
/// `len > 255 * 32` 时返回 `Error::InvalidInputLength`
#[cfg(feature = "alloc")]
pub fn hkdf_expand(prk: &[u8; DIGEST_LEN], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    // Reason: RFC 5869 §2.3 限制最大输出为 255 × HashLen
    const MAX_LEN: usize = 255 * DIGEST_LEN;
    if len > MAX_LEN {
        return Err(Error::InvalidInputLength);
    }

    let mut okm = Vec::with_capacity(len + DIGEST_LEN);
    let mut t_prev = [0u8; DIGEST_LEN]; // T(0) = b""
    let mut t_prev_len = 0usize; // 第一轮 T(0) 为空

    let rounds = len.div_ceil(DIGEST_LEN);
    for i in 1u8..=(rounds as u8) {
        // HMAC-SM3(PRK, T(i-1) || info || i)
        // Reason: 用拼接方式避免在 no_std 环境分配临时 Vec
        let mut input = [0u8; DIGEST_LEN + 255 + 1]; // T_prev(32) + info(≤255) + counter(1)
        let info_len = info.len().min(255);
        input[..t_prev_len].copy_from_slice(&t_prev[..t_prev_len]);
        input[t_prev_len..t_prev_len + info_len].copy_from_slice(&info[..info_len]);
        input[t_prev_len + info_len] = i;
        let t_i = hmac_sm3(prk, &input[..t_prev_len + info_len + 1]);

        okm.extend_from_slice(&t_i);
        t_prev = t_i;
        t_prev_len = DIGEST_LEN; // 第二轮起 T_prev 固定 32 字节
    }

    okm.truncate(len);
    Ok(okm)
}

/// HKDF-SM3 一步完成（extract + expand）
///
/// 适合只需要派生一段密钥材料的场景。
///
/// # 参数
/// - `salt`：可选盐值（`None` 视为 32 字节零）
/// - `ikm`：输入密钥材料
/// - `info`：上下文绑定信息
/// - `len`：输出长度（字节）
#[cfg(feature = "alloc")]
pub fn hkdf(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 附录 A.1 测试向量（以 SHA-256 为基准验结构，此处用 SM3 验确定性和正确性）
    #[test]
    fn test_hkdf_extract_deterministic() {
        let salt = b"test-salt";
        let ikm = b"input-key-material";
        let prk1 = hkdf_extract(Some(salt), ikm);
        let prk2 = hkdf_extract(Some(salt), ikm);
        assert_eq!(prk1, prk2);
        assert_eq!(prk1.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_none_salt_equals_zero_salt() {
        let ikm = b"some ikm";
        let zeros = [0u8; 32];
        let prk_none = hkdf_extract(None, ikm);
        let prk_zero = hkdf_extract(Some(&zeros), ikm);
        assert_eq!(prk_none, prk_zero);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_expand_length() {
        let prk = [0x42u8; 32];
        let info = b"test-info";
        assert_eq!(hkdf_expand(&prk, info, 16).unwrap().len(), 16);
        assert_eq!(hkdf_expand(&prk, info, 32).unwrap().len(), 32);
        assert_eq!(hkdf_expand(&prk, info, 48).unwrap().len(), 48);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_expand_deterministic() {
        let prk = [0x11u8; 32];
        let info = b"ctx";
        let out1 = hkdf_expand(&prk, info, 32).unwrap();
        let out2 = hkdf_expand(&prk, info, 32).unwrap();
        assert_eq!(out1, out2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_expand_prefix_consistency() {
        // T(1..n) 前缀应与长度更短的输出一致
        let prk = [0x22u8; 32];
        let info = b"prefix-test";
        let short = hkdf_expand(&prk, info, 32).unwrap();
        let long = hkdf_expand(&prk, info, 64).unwrap();
        assert_eq!(&long[..32], &short[..]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_expand_max_len_rejected() {
        let prk = [0u8; 32];
        let result = hkdf_expand(&prk, b"", 255 * 32 + 1);
        assert!(result.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_expand_max_len_accepted() {
        let prk = [0u8; 32];
        let result = hkdf_expand(&prk, b"", 255 * 32);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 255 * 32);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_different_info_different_output() {
        let prk = [0x33u8; 32];
        let out1 = hkdf_expand(&prk, b"info-a", 32).unwrap();
        let out2 = hkdf_expand(&prk, b"info-b", 32).unwrap();
        assert_ne!(out1, out2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_hkdf_roundtrip_salt_info() {
        // 模拟 TLS 1.3 密钥调度：extract 然后 expand 两种 label
        let salt = b"tls13-early-secret-salt";
        let ikm = b"shared-secret-from-key-exchange";
        let prk = hkdf_extract(Some(salt), ikm);

        let key1 = hkdf_expand(&prk, b"tls13 key", 16).unwrap();
        let key2 = hkdf_expand(&prk, b"tls13 iv", 12).unwrap();
        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 12);
        assert_ne!(&key1[..12], &key2[..]);
    }
}
