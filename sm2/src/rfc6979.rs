//! RFC 6979 确定性 k 值生成（使用 HMAC-SM3）
//!
//! 实现 RFC 6979 §3.2 的 HMAC-DRBG，以 SM3 作为哈希函数。
//!
//! # 安全关键点
//!
//! 此模块消除了 SM2 签名对外部 RNG 的依赖。对于相同的 (私钥, 消息摘要) 对，
//! 生成的 k 值完全确定，从根本上消除了 RNG 故障或偏差导致私钥泄露的风险。
//!
//! # 参考
//!
//! - RFC 6979 §3.2: <https://www.rfc-editor.org/rfc/rfc6979#section-3.2>

use crypto_bigint::{Zero, U256};
use sm3::Digest;
use zeroize::Zeroize;

use crate::field::GROUP_ORDER;

// SM3 输出长度（字节）
const HASH_LEN: usize = 32;

/// 内部 HMAC-SM3 实现（仅供 RFC 6979 使用）
///
/// HMAC(K, m) = SM3((K ^ opad) || SM3((K ^ ipad) || m))
///
/// Reason: sm3 sub-crate 没有导出 HMAC，我们在内部实现以避免新增依赖。
/// 块大小 64 字节，与 SM3 的 BlockSize 一致。
struct HmacSm3 {
    /// 外层密钥 K ^ opad（已预处理）
    opad_key: [u8; 64],
    /// 内层哈希上下文（已吸收 K ^ ipad）
    inner: sm3::Sm3,
}

impl HmacSm3 {
    /// 以 key 初始化 HMAC-SM3 上下文
    fn new(key: &[u8; 32]) -> Self {
        let mut ipad_key = [0x36u8; 64];
        let mut opad_key = [0x5cu8; 64];
        // Reason: key 长度 32 字节 < 块大小 64，直接 XOR 前 32 字节
        for (i, &b) in key.iter().enumerate() {
            ipad_key[i] ^= b;
            opad_key[i] ^= b;
        }
        let mut inner = sm3::Sm3::new();
        inner.update(&ipad_key);
        ipad_key.zeroize();
        HmacSm3 { opad_key, inner }
    }

    /// 向内层哈希追加数据
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// 计算 HMAC 值（消耗 self）
    fn finalize(self) -> [u8; HASH_LEN] {
        // Reason: Drop trait 阻止直接 move self.inner，clone 一次即可
        let inner_hash: [u8; HASH_LEN] = self.inner.clone().finalize().into();
        let mut outer = sm3::Sm3::new();
        outer.update(&self.opad_key);
        outer.update(&inner_hash);
        outer.finalize().into()
    }
}

impl Drop for HmacSm3 {
    fn drop(&mut self) {
        self.opad_key.zeroize();
    }
}

/// HMAC-SM3 一次性计算：`HMAC(key, msg1 || msg2 || ...)`
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut mac = HmacSm3::new(key);
    for part in parts {
        mac.update(part);
    }
    mac.finalize()
}

/// RFC 6979 §3.2 确定性 k 值生成
///
/// 输入：
/// - `x`: 私钥字节（32 字节，big-endian）
/// - `h1`: 消息摘要 e（32 字节，已经过 Z||M 预处理的 SM3 输出）
///
/// 输出：满足 `0 < k < n` 的确定性标量 k
///
/// # 安全关键点
///
/// 对于相同的 (x, h1) 输入，此函数总是返回相同的 k，
/// 从根本上消除了签名过程对 RNG 质量的依赖。
pub(crate) fn generate_k(x: &[u8; 32], h1: &[u8; 32]) -> U256 {
    // RFC 6979 §3.2 步骤 b/c: 初始化 V 和 K
    //
    // V = 0x01 0x01 ... 0x01 (hlen 个字节)
    // K = 0x00 0x00 ... 0x00 (hlen 个字节)
    let mut v = [0x01u8; HASH_LEN];
    let mut k = [0x00u8; HASH_LEN];

    // 步骤 d: K = HMAC_K(V || 0x00 || x || h1)
    k = hmac(&k, &[&v, &[0x00u8], x, h1]);

    // 步骤 e: V = HMAC_K(V)
    v = hmac(&k, &[&v]);

    // 步骤 f: K = HMAC_K(V || 0x01 || x || h1)
    k = hmac(&k, &[&v, &[0x01u8], x, h1]);

    // 步骤 g: V = HMAC_K(V)
    v = hmac(&k, &[&v]);

    // 步骤 h: 循环生成候选 k
    loop {
        // h2: V = HMAC_K(V)
        v = hmac(&k, &[&v]);

        // bits2int(V): 直接作为 big-endian 256-bit 整数
        let candidate = U256::from_be_slice(&v);

        // 检查 0 < k < n（group order）
        // Reason: CT 比较 — candidate.is_zero() 和 candidate >= GROUP_ORDER
        let is_zero: bool = candidate.is_zero().into();
        let ge_n: bool = (candidate >= GROUP_ORDER).into();

        if !is_zero && !ge_n {
            // 找到合法 k，清零临时数据后返回
            v.zeroize();
            k.zeroize();
            return candidate;
        }

        // 步骤 h3 更新（不满足时继续）
        k = hmac(&k, &[&v, &[0x00u8]]);
        v = hmac(&k, &[&v]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::GROUP_ORDER;

    /// 确定性验证：相同输入总产生相同 k
    #[test]
    fn test_generate_k_deterministic() {
        let x = [0x01u8; 32];
        let h1 = [0x02u8; 32];
        let k1 = generate_k(&x, &h1);
        let k2 = generate_k(&x, &h1);
        assert_eq!(k1, k2, "RFC 6979 k must be deterministic");
    }

    /// k 必须在有效范围 (0, n)
    #[test]
    fn test_generate_k_range() {
        let x = [0x42u8; 32];
        let h1 = [0xABu8; 32];
        let k = generate_k(&x, &h1);
        assert!(!bool::from(k.is_zero()), "k must not be zero");
        assert!(k < GROUP_ORDER, "k must be less than group order");
    }

    /// 不同消息产生不同 k
    #[test]
    fn test_generate_k_different_msgs() {
        let x = [0x01u8; 32];
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        let k1 = generate_k(&x, &h1);
        let k2 = generate_k(&x, &h2);
        assert_ne!(k1, k2, "different messages must produce different k values");
    }
}
