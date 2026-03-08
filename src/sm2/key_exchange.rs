//! SM2 密钥交换协议（GB/T 32918.3-2016）
//!
//! 提供两种密钥交换方式：
//! - `ecdh`: 简单 SM2-ECDH 共享密钥计算（适配 TLS/rustls）
//! - `exchange_a` / `exchange_b`: 完整 GB/T 32918.3 密钥交换协议（带确认哈希）

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crypto_bigint::{Zero, U256};
use rand_core::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::sm2::ec::{AffinePoint, JacobianPoint};
use crate::sm2::field::{fn_add, fn_mul, fp_to_bytes, Fn, GROUP_ORDER_MINUS_1};
use crate::sm2::get_z;
use crate::sm3::Sm3Hasher;

// ── x̄ 辅助函数（GB/T 32918.3 核心运算）─────────────────────────────────────────

/// 计算 x̄ = 2^w + (x & (2^w - 1))，其中 w = ⌈(⌈log2(n)⌉ / 2)⌉ - 1 = 127
///
/// 对 SM2 256 位群阶，w=127。在大端 32 字节表示中：
/// - 清除高 128 位（bytes[0..16]），保留低 128 位
/// - 设 bytes[16] 的 bit7 = 1（即加 2^127）
fn x_bar(x_bytes: &[u8; 32]) -> U256 {
    let mut buf = [0u8; 32];
    // Reason: 保留 x 的低 128 位（bytes[16..32]），高 128 位清零
    buf[16..32].copy_from_slice(&x_bytes[16..32]);
    // 设 bit 127（bytes[16] 的最高位）
    buf[16] |= 0x80;
    U256::from_be_slice(&buf)
}

// ── EphemeralKey（临时密钥对）────────────────────────────────────────────────────

/// SM2 密钥交换临时密钥对（离开作用域自动清零）
///
/// 用于密钥交换协议中的临时私钥和对应公钥。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKey {
    r_bytes: [u8; 32],
    #[zeroize(skip)]
    r_point: [u8; 65],
}

impl EphemeralKey {
    /// 生成临时密钥对
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        loop {
            let mut r_bytes = [0u8; 32];
            rng.fill_bytes(&mut r_bytes);
            let r = U256::from_be_slice(&r_bytes);
            if bool::from(r.is_zero()) || r >= GROUP_ORDER_MINUS_1 {
                r_bytes.zeroize();
                continue;
            }
            let r_jac = JacobianPoint::scalar_mul_g(&r);
            // Reason: r 在合法范围内，scalar_mul_g 不会产生无穷远点
            let r_aff = r_jac.to_affine().expect("valid r produces valid point");
            return EphemeralKey {
                r_bytes,
                r_point: r_aff.to_bytes(),
            };
        }
    }

    /// 从指定标量创建临时密钥对（测试用）
    pub fn from_scalar(r: &U256) -> Result<Self, Error> {
        if bool::from(r.is_zero()) || *r >= GROUP_ORDER_MINUS_1 {
            return Err(Error::InvalidPrivateKey);
        }
        let r_jac = JacobianPoint::scalar_mul_g(r);
        let r_aff = r_jac.to_affine().map_err(|_| Error::InvalidPrivateKey)?;
        Ok(EphemeralKey {
            r_bytes: r.to_be_bytes(),
            r_point: r_aff.to_bytes(),
        })
    }

    /// 获取临时公钥（发送给对方）
    pub fn public_key(&self) -> &[u8; 65] {
        &self.r_point
    }
}

// ── 简单 ECDH ──────────────────────────────────────────────────────────────────

/// 简单 SM2-ECDH 共享密钥计算
///
/// 计算 shared = my_priv · peer_pub，返回共享点的 x 坐标（32 字节）。
/// 适用于 TLS/rustls 等只需要原始 ECDH 共享密钥的场景。
///
/// # 参数
/// - `my_priv`: 己方私钥
/// - `peer_pub`: 对方公钥（65 字节，04||x||y）
///
/// # 错误
/// - `InvalidPublicKey`: 公钥格式错误或不在曲线上
/// - `PointAtInfinity`: 共享点为无穷远（不应发生于合法输入）
pub fn ecdh(my_priv: &crate::sm2::PrivateKey, peer_pub: &[u8; 65]) -> Result<[u8; 32], Error> {
    let peer = AffinePoint::from_bytes(peer_pub)?;
    let d = U256::from_be_slice(my_priv.as_bytes());
    let peer_jac = JacobianPoint::from_affine(&peer);
    let shared = JacobianPoint::scalar_mul(&d, &peer_jac);
    let shared_aff = shared.to_affine()?;
    Ok(fp_to_bytes(&shared_aff.x))
}

/// 从变长切片执行 SM2-ECDH（rustls `ActiveKeyExchange::complete` 适配）
///
/// 等同于 `ecdh`，但接受 `&[u8]` 而非 `&[u8; 65]`，省去调用方的长度转换。
///
/// # 错误
/// - `InvalidInputLength`: peer_pub 长度不等于 65
/// - `InvalidPublicKey` / `PointAtInfinity`: 同 `ecdh`
pub fn ecdh_from_slice(
    my_priv: &crate::sm2::PrivateKey,
    peer_pub: &[u8],
) -> Result<[u8; 32], Error> {
    let pub_fixed: &[u8; 65] = peer_pub.try_into().map_err(|_| Error::InvalidInputLength)?;
    ecdh(my_priv, pub_fixed)
}

// ── 完整密钥交换协议（GB/T 32918.3）──────────────────────────────────────────────

/// 密钥交换结果
#[cfg(feature = "alloc")]
pub struct ExchangeResult {
    /// 协商出的共享密钥
    pub key: Vec<u8>,
    /// 己方确认哈希（发给对方验证）
    pub s_self: [u8; 32],
    /// 对方确认哈希（用于验证对方发来的值）
    pub s_peer: [u8; 32],
}

/// 发起方 A 执行密钥交换
///
/// # 参数
/// - `klen`: 期望密钥长度（字节）
/// - `id_a`: 发起方用户 ID
/// - `id_b`: 响应方用户 ID
/// - `pri_key_a`: 发起方私钥
/// - `pub_key_a`: 发起方公钥（65 字节）
/// - `pub_key_b`: 响应方公钥（65 字节）
/// - `eph_key_a`: 发起方临时密钥
/// - `r_b`: 响应方临时公钥（65 字节）
#[cfg(feature = "alloc")]
#[allow(clippy::too_many_arguments)]
pub fn exchange_a(
    klen: usize,
    id_a: &[u8],
    id_b: &[u8],
    pri_key_a: &crate::sm2::PrivateKey,
    pub_key_a: &[u8; 65],
    pub_key_b: &[u8; 65],
    eph_key_a: &EphemeralKey,
    r_b: &[u8; 65],
) -> Result<ExchangeResult, Error> {
    compute_shared(
        true, klen, id_a, id_b, pri_key_a, pub_key_a, pub_key_b, eph_key_a, r_b,
    )
}

/// 响应方 B 执行密钥交换
///
/// # 参数
/// - `klen`: 期望密钥长度（字节）
/// - `id_a`: 发起方用户 ID
/// - `id_b`: 响应方用户 ID
/// - `pri_key_b`: 响应方私钥
/// - `pub_key_a`: 发起方公钥（65 字节）
/// - `pub_key_b`: 响应方公钥（65 字节）
/// - `eph_key_b`: 响应方临时密钥
/// - `r_a`: 发起方临时公钥（65 字节）
#[cfg(feature = "alloc")]
#[allow(clippy::too_many_arguments)]
pub fn exchange_b(
    klen: usize,
    id_a: &[u8],
    id_b: &[u8],
    pri_key_b: &crate::sm2::PrivateKey,
    pub_key_a: &[u8; 65],
    pub_key_b: &[u8; 65],
    eph_key_b: &EphemeralKey,
    r_a: &[u8; 65],
) -> Result<ExchangeResult, Error> {
    compute_shared(
        false, klen, id_a, id_b, pri_key_b, pub_key_a, pub_key_b, eph_key_b, r_a,
    )
}

/// 内部共享计算
///
/// `is_initiator`: true 表示发起方 A，false 表示响应方 B
#[cfg(feature = "alloc")]
#[allow(clippy::too_many_arguments)]
fn compute_shared(
    is_initiator: bool,
    klen: usize,
    id_a: &[u8],
    id_b: &[u8],
    pri_key_self: &crate::sm2::PrivateKey,
    pub_key_a: &[u8; 65],
    pub_key_b: &[u8; 65],
    eph_key_self: &EphemeralKey,
    r_peer: &[u8; 65],
) -> Result<ExchangeResult, Error> {
    // 计算 ZA、ZB
    let z_a = get_z(id_a, pub_key_a);
    let z_b = get_z(id_b, pub_key_b);

    // 解析临时公钥坐标
    let r_self_aff = AffinePoint::from_bytes(eph_key_self.public_key())?;
    let r_peer_aff = AffinePoint::from_bytes(r_peer)?;

    // 计算 x̄_self 和 x̄_peer
    let x_self_bytes = fp_to_bytes(&r_self_aff.x);
    let x_peer_bytes = fp_to_bytes(&r_peer_aff.x);
    let x_bar_self = x_bar(&x_self_bytes);
    let x_bar_peer = x_bar(&x_peer_bytes);

    // t = (d_self + x̄_self · r_self) mod n
    let d_self = U256::from_be_slice(pri_key_self.as_bytes());
    let r_self = U256::from_be_slice(&eph_key_self.r_bytes);
    let t_fn = fn_add(
        &Fn::new(&d_self),
        &fn_mul(&Fn::new(&x_bar_self), &Fn::new(&r_self)),
    );

    // V/U = t · (peer_pub + x̄_peer · R_peer)
    // Reason: 先计算 x̄_peer · R_peer（标量乘），再加 peer_pub（仿射点）
    let peer_pub_bytes = if is_initiator { pub_key_b } else { pub_key_a };
    let peer_pub_aff = AffinePoint::from_bytes(peer_pub_bytes)?;
    let peer_pub_jac = JacobianPoint::from_affine(&peer_pub_aff);
    let r_peer_jac = JacobianPoint::from_affine(&r_peer_aff);
    let x_bar_peer_r = JacobianPoint::scalar_mul(&x_bar_peer, &r_peer_jac);
    let combined = JacobianPoint::add(&peer_pub_jac, &x_bar_peer_r);
    let t = t_fn.retrieve();
    let v_point = JacobianPoint::scalar_mul(&t, &combined);
    let v_aff = v_point.to_affine().map_err(|_| Error::KeyExchangeFailed)?;

    let xv = fp_to_bytes(&v_aff.x);
    let yv = fp_to_bytes(&v_aff.y);

    // K = KDF(xV || yV || ZA || ZB, klen)
    let mut kdf_input = Vec::with_capacity(32 + 32 + 32 + 32);
    kdf_input.extend_from_slice(&xv);
    kdf_input.extend_from_slice(&yv);
    kdf_input.extend_from_slice(&z_a);
    kdf_input.extend_from_slice(&z_b);
    let key = crate::sm2::kdf::kdf(&kdf_input, klen);

    // KDF 输出全零时返回错误（防弱密钥）
    if key.iter().all(|&b| b == 0) {
        return Err(Error::KeyExchangeFailed);
    }

    // 确认哈希
    // (x1,y1) 始终是 RA（发起方），(x2,y2) 始终是 RB（响应方）
    let (x1, y1, x2, y2) = if is_initiator {
        (
            fp_to_bytes(&r_self_aff.x),
            fp_to_bytes(&r_self_aff.y),
            fp_to_bytes(&r_peer_aff.x),
            fp_to_bytes(&r_peer_aff.y),
        )
    } else {
        (
            fp_to_bytes(&r_peer_aff.x),
            fp_to_bytes(&r_peer_aff.y),
            fp_to_bytes(&r_self_aff.x),
            fp_to_bytes(&r_self_aff.y),
        )
    };

    // 内部哈希 hash_v = SM3(xV || ZA || ZB || x1 || y1 || x2 || y2)
    let mut h = Sm3Hasher::new();
    h.update(&xv);
    h.update(&z_a);
    h.update(&z_b);
    h.update(&x1);
    h.update(&y1);
    h.update(&x2);
    h.update(&y2);
    let hash_v = h.finalize();

    // S1 = SM3(0x02 || yV || hash_v) — 己方若为 B，则 S1 是己方确认值
    let s1 = {
        let mut h = Sm3Hasher::new();
        h.update(&[0x02]);
        h.update(&yv);
        h.update(&hash_v);
        h.finalize()
    };

    // SA = SM3(0x03 || yV || hash_v)
    let sa = {
        let mut h = Sm3Hasher::new();
        h.update(&[0x03]);
        h.update(&yv);
        h.update(&hash_v);
        h.finalize()
    };

    // Reason: 发起方 A 的确认哈希是 SA（0x03），响应方 B 的确认哈希是 S1（0x02）
    let (s_self, s_peer) = if is_initiator {
        (sa, s1) // A 发送 SA 给 B 验证，A 验证 B 发来的 S1
    } else {
        (s1, sa) // B 发送 S1 给 A 验证，B 验证 A 发来的 SA
    };

    Ok(ExchangeResult {
        key,
        s_self,
        s_peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::PrivateKey;

    #[allow(dead_code)]
    struct FakeRng(#[allow(dead_code)] [u8; 32]);
    impl RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for (i, b) in dest.iter_mut().enumerate() {
                *b = self.0[i % 32];
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn test_x_bar() {
        // x = 1（低 128 位只有 bit 0）
        let mut x_bytes = [0u8; 32];
        x_bytes[31] = 0x01;
        let result = x_bar(&x_bytes);
        // 期望 2^127 + 1
        let mut expected = [0u8; 32];
        expected[16] = 0x80;
        expected[31] = 0x01;
        assert_eq!(result, U256::from_be_slice(&expected));
    }

    #[test]
    fn test_x_bar_high_bits_cleared() {
        // x 有高 128 位数据，应被清除
        let x_bytes = [0xFFu8; 32];
        let result = x_bar(&x_bytes);
        // 低 128 位全 1 + 2^127 设置位 = 0x80 FF...FF 后 16 字节加上 2^127
        // 高 16 字节应为 0，bytes[16] = 0xFF | 0x80 = 0xFF
        let mut expected = [0u8; 32];
        expected[16..32].copy_from_slice(&[0xFF; 16]);
        expected[16] |= 0x80; // 已经是 0xFF，不变
        assert_eq!(result, U256::from_be_slice(&expected));
    }

    #[test]
    fn test_ecdh_roundtrip() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let d_b: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];

        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();
        let pri_b = PrivateKey::from_bytes(&d_b).unwrap();
        let pub_a = pri_a.public_key();
        let pub_b = pri_b.public_key();

        // A 用 B 的公钥算 ECDH，B 用 A 的公钥算 ECDH，结果应一致
        let shared_a = ecdh(&pri_a, &pub_b).unwrap();
        let shared_b = ecdh(&pri_b, &pub_a).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_ecdh_invalid_pubkey() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();

        // 无效公钥（全零 y 坐标不在曲线上）
        let mut bad_pub = [0x04u8; 65];
        bad_pub[1] = 0x01;
        assert!(ecdh(&pri_a, &bad_pub).is_err());
    }

    #[test]
    fn test_ecdh_from_slice_length_check() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();

        // 长度不对应报 InvalidInputLength
        assert!(ecdh_from_slice(&pri_a, &[0x04u8; 64]).is_err());
        assert!(ecdh_from_slice(&pri_a, &[0x04u8; 66]).is_err());
    }

    #[test]
    fn test_ecdh_from_slice_equals_ecdh() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let d_b: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];
        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();
        let pri_b = PrivateKey::from_bytes(&d_b).unwrap();
        let pub_b = pri_b.public_key();

        let r1 = ecdh(&pri_a, &pub_b).unwrap();
        let r2 = ecdh_from_slice(&pri_a, &pub_b).unwrap();
        assert_eq!(r1, r2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_exchange_roundtrip() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let d_b: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];

        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();
        let pri_b = PrivateKey::from_bytes(&d_b).unwrap();
        let pub_a = pri_a.public_key();
        let pub_b = pri_b.public_key();

        let id_a = b"Alice@test.com";
        let id_b = b"Bob@test.com";

        // 生成临时密钥
        let ra_scalar =
            U256::from_be_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let rb_scalar =
            U256::from_be_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        let eph_a = EphemeralKey::from_scalar(&ra_scalar).unwrap();
        let eph_b = EphemeralKey::from_scalar(&rb_scalar).unwrap();

        let result_a = exchange_a(
            16,
            id_a,
            id_b,
            &pri_a,
            &pub_a,
            &pub_b,
            &eph_a,
            eph_b.public_key(),
        )
        .unwrap();

        let result_b = exchange_b(
            16,
            id_a,
            id_b,
            &pri_b,
            &pub_a,
            &pub_b,
            &eph_b,
            eph_a.public_key(),
        )
        .unwrap();

        // 协商出的密钥应相同
        assert_eq!(result_a.key, result_b.key);
        assert!(!result_a.key.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_exchange_confirmation() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let d_b: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];

        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();
        let pri_b = PrivateKey::from_bytes(&d_b).unwrap();
        let pub_a = pri_a.public_key();
        let pub_b = pri_b.public_key();

        let id_a = b"1234567812345678";
        let id_b = b"1234567812345678";

        let ra_scalar =
            U256::from_be_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let rb_scalar =
            U256::from_be_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        let eph_a = EphemeralKey::from_scalar(&ra_scalar).unwrap();
        let eph_b = EphemeralKey::from_scalar(&rb_scalar).unwrap();

        let result_a = exchange_a(
            16,
            id_a,
            id_b,
            &pri_a,
            &pub_a,
            &pub_b,
            &eph_a,
            eph_b.public_key(),
        )
        .unwrap();

        let result_b = exchange_b(
            16,
            id_a,
            id_b,
            &pri_b,
            &pub_a,
            &pub_b,
            &eph_b,
            eph_a.public_key(),
        )
        .unwrap();

        // 确认哈希交叉验证：A.s_peer == B.s_self，B.s_peer == A.s_self
        assert_eq!(result_a.s_peer, result_b.s_self);
        assert_eq!(result_b.s_peer, result_a.s_self);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_exchange_different_ids() {
        let d_a: [u8; 32] = [
            0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
            0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
            0x4d, 0xf7, 0xc5, 0xb8,
        ];
        let d_b: [u8; 32] = [
            0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
            0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
            0xea, 0xc1, 0xbc, 0x21,
        ];

        let pri_a = PrivateKey::from_bytes(&d_a).unwrap();
        let pri_b = PrivateKey::from_bytes(&d_b).unwrap();
        let pub_a = pri_a.public_key();
        let pub_b = pri_b.public_key();

        let ra_scalar =
            U256::from_be_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let rb_scalar =
            U256::from_be_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");

        // 使用不同 ID 组合
        let eph_a1 = EphemeralKey::from_scalar(&ra_scalar).unwrap();
        let eph_b1 = EphemeralKey::from_scalar(&rb_scalar).unwrap();
        let result_1 = exchange_a(
            16,
            b"ID_A_1",
            b"ID_B_1",
            &pri_a,
            &pub_a,
            &pub_b,
            &eph_a1,
            eph_b1.public_key(),
        )
        .unwrap();

        let eph_a2 = EphemeralKey::from_scalar(&ra_scalar).unwrap();
        let eph_b2 = EphemeralKey::from_scalar(&rb_scalar).unwrap();
        let result_2 = exchange_a(
            16,
            b"ID_A_2",
            b"ID_B_2",
            &pri_a,
            &pub_a,
            &pub_b,
            &eph_a2,
            eph_b2.public_key(),
        )
        .unwrap();

        // 不同 ID 应产生不同密钥
        assert_ne!(result_1.key, result_2.key);
    }
}
