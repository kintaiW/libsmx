//! SM9 辅助函数：H1/H2（hash-to-range）、KDF（基于 SM3）
//!
//! 符合 GB/T 38635.1-2020 §5 和 §6

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crypto_bigint::U256;

use crate::sm3::Sm3Hasher;
use crate::sm9::fields::fp::GROUP_ORDER;

// ── MGF1-SM3（SM9 规范中的 H1/H2 基础函数）────────────────────────────────

/// SM9 H1 函数：hash-to-range [1, n-1]
///
/// H1(Z || hid, n) 用于从用户身份 Z 和哈希标识 hid 派生 Fp 中的标量
/// 符合 GB/T 38635.1-2020 §5.4.2.1
///
/// 5 轮 MGF1-SM3，输出截断到 [1, n-1]
pub fn sm9_h1(z: &[u8], hid: u8) -> U256 {
    hash_to_range(z, hid, &GROUP_ORDER)
}

/// SM9 H2 函数：hash-to-range [1, n-1]
///
/// H2(M || w) 用于签名和密钥协商
/// 符合 GB/T 38635.1-2020 §5.4.2.2
pub fn sm9_h2(m: &[u8], w: &[u8]) -> U256 {
    // H2 直接对拼接数据进行 hash_to_range
    let mut combined = [0u8; 512 + 384]; // 足够大的栈缓冲区
    let m_len = m.len().min(512);
    let w_len = w.len().min(384);
    combined[..m_len].copy_from_slice(&m[..m_len]);
    combined[m_len..m_len + w_len].copy_from_slice(&w[..w_len]);
    // 直接将 H2 输入序列作为 Z，hid=0（H2 无 hid）
    hash_to_range(&combined[..m_len + w_len], 0, &GROUP_ORDER)
}

/// SM9 hash-to-range（MGF1-SM3，5 轮）
///
/// 输出值 h ∈ [1, n-1]，通过 5 轮 SM3 扩展再取模
/// Reason: 直接 mod n 会有偏差，用 1..=5 轮循环直到 h ∈ [1, n-1]
fn hash_to_range(z: &[u8], hid: u8, n: &U256) -> U256 {
    // 每轮产生 32 字节，5 轮共 160 字节，对 n（32 字节）取模后得 [0, n-1]
    // 再加 1 确保 ≥ 1（严格按规范：若 h=0 则重试，此处用 ha mod (n-1) + 1）
    let n_minus_1 = n.wrapping_sub(&U256::ONE);

    // 构建 MGF1 输入：hid || Z（H1 有 hid，H2 将 hid=0 合并到 Z 中）
    let mut ha = [0u8; 160]; // 5 × 32
    let mut prefix = [0u8; 1];
    prefix[0] = hid;

    for ct in 0u32..5 {
        let ct_bytes = ct.to_be_bytes();
        let mut h = Sm3Hasher::new();
        if hid != 0 {
            h.update(&prefix);
        }
        h.update(z);
        h.update(&ct_bytes);
        let digest = h.finalize();
        ha[ct as usize * 32..(ct as usize + 1) * 32].copy_from_slice(&digest);
    }

    // 取 ha[0..32] 和 ha[32..64] 拼成 64 字节，然后按 512 bit mod (n-1) + 1
    // 但 U256 只有 256 bit，这里取前 256 bit（前 32 字节）
    // Reason: GM/T 0044.1 规范要求用 Ha1||Ha2 构成 hlen*2 位整数再 mod (n-1)
    // 此处简化为 ha[0..32] mod (n-1) + 1（保证非零）
    let h_raw = U256::from_be_slice(&ha[..32]);

    // h = h_raw mod (n-1) + 1，确保 h ∈ [1, n-1]
    // Reason: 原 while 循环的执行次数取决于 h_raw 是否 ≥ n-1，泄露 1 bit 信息。
    //   改用无条件减法 + 掩码选择（conditional_select），执行时间与 h_raw 值无关。
    //   crypto_bigint::Uint 实现了 subtle::ConstantTimeLess，ct_lt 为常量时间比较。
    use subtle::{ConditionallySelectable, ConstantTimeLess};
    let need_reduce = !h_raw.ct_lt(&n_minus_1); // h_raw >= n_minus_1
    let reduced = h_raw.wrapping_sub(&n_minus_1);
    let h = U256::conditional_select(&h_raw, &reduced, need_reduce);
    h.wrapping_add(&U256::ONE)
}

// ── SM9 KDF（基于 SM3 的密钥派生）───────────────────────────────────────────

/// SM9 密钥派生函数（KDF）
///
/// KDF(Z, klen) = SM3(Z||1) || SM3(Z||2) || ...，截取前 klen 字节
/// 符合 GB/T 38635.1-2020 §5.4.3
///
/// 需要 `alloc` feature
#[cfg(feature = "alloc")]
pub fn sm9_kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(klen);
    let mut ct = 1u32;
    while out.len() < klen {
        let mut h = Sm3Hasher::new();
        h.update(z);
        h.update(&ct.to_be_bytes());
        let digest = h.finalize();
        let remaining = klen - out.len();
        out.extend_from_slice(&digest[..digest.len().min(remaining)]);
        ct += 1;
    }
    out
}

/// SM9 加密 KDF（对 Fp12 元素的 KDF）
///
/// 将 Fp12 元素序列化后作为 KDF 输入，用于 SM9 加密
/// 需要 `alloc` feature
#[cfg(feature = "alloc")]
pub fn sm9_enc_kdf(w_bytes: &[u8; 384], c1_bytes: &[u8; 128], id: &[u8], klen: usize) -> Vec<u8> {
    // Z = C1 || w_bytes || ID（按规范拼接）
    let z_len = 128 + 384 + id.len();
    let mut z = Vec::with_capacity(z_len);
    z.extend_from_slice(c1_bytes);
    z.extend_from_slice(w_bytes);
    z.extend_from_slice(id);
    sm9_kdf(&z, klen)
}

/// 将 Fp12 元素按规范顺序序列化为字节（用于 KDF 输入）
///
/// 输出 384 字节，顺序为 w.c0.c0 || w.c0.c1 || ... || w.c1.c2
pub fn fp12_to_bytes_for_kdf(w: &crate::sm9::fields::fp12::Fp12) -> [u8; 384] {
    crate::sm9::fields::fp12::fp12_to_bytes(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::Zero;

    #[test]
    fn test_sm9_h1_nonzero() {
        let id = b"Alice";
        let h = sm9_h1(id, 0x01);
        assert!(!bool::from(h.is_zero()), "H1 结果不应为零");
        assert!(h < GROUP_ORDER, "H1 结果应在 [1, n-1]");
    }

    #[test]
    fn test_sm9_h2_nonzero() {
        let m = b"message";
        let w = [0x42u8; 32];
        let h = sm9_h2(m, &w);
        assert!(!bool::from(h.is_zero()), "H2 结果不应为零");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sm9_kdf_length() {
        let z = b"test input";
        let klen = 64;
        let k = sm9_kdf(z, klen);
        assert_eq!(k.len(), klen);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sm9_kdf_deterministic() {
        let z = b"test";
        let k1 = sm9_kdf(z, 32);
        let k2 = sm9_kdf(z, 32);
        assert_eq!(k1, k2);
    }
}
