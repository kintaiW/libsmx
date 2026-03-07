//! SM2 KDF 密钥派生函数（GB/T 32918.4-2016 §5.4.3）
//!
//! KDF(Z, klen) = ‖_{i=1}^{⌈klen/32⌉} SM3(Z ‖ CT_i)
//! 其中 CT_i 为 32-bit 大端计数器，从 1 开始。

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::sm3::Sm3Hasher;

/// SM2/SM9 KDF 密钥派生函数
///
/// # 参数
/// - `z`: 输入密钥材料（共享点坐标等）
/// - `klen`: 期望输出字节数
///
/// # 返回
/// 长度为 `klen` 的派生密钥字节序列（`alloc` feature 下可用）
#[cfg(feature = "alloc")]
pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(klen + 32);
    let mut counter: u32 = 1;
    while result.len() < klen {
        // 每轮: SM3(Z || CT_i)
        let mut h = Sm3Hasher::new();
        h.update(z);
        h.update(&counter.to_be_bytes());
        result.extend_from_slice(&h.finalize());
        counter += 1;
    }
    result.truncate(klen);
    result
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_length() {
        let z = b"test input";
        assert_eq!(kdf(z, 32).len(), 32);
        assert_eq!(kdf(z, 48).len(), 48);
        assert_eq!(kdf(z, 1).len(), 1);
    }

    #[test]
    fn test_kdf_deterministic() {
        let z = b"shared secret";
        assert_eq!(kdf(z, 32), kdf(z, 32));
    }

    #[test]
    fn test_kdf_different_lengths() {
        // 64 字节输出应与两次 32 字节拼接一致（即第一块完全相同）
        let z = b"input";
        let k32 = kdf(z, 32);
        let k64 = kdf(z, 64);
        assert_eq!(&k64[..32], &k32[..]);
    }
}
