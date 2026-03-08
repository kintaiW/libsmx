//! BLS 签名方案（基于 SM9 BN256 配对）
//!
//! 实现 draft-irtf-cfrg-bls-signature-06 的 minimal-signature-size 变体：
//! - 公钥在 G2（128 字节），签名在 G1（65 字节）
//! - 确定性签名（无随机数 nonce）
//! - 支持签名聚合和门限签名
//!
//! # 安全说明
//! BN256 曲线的实际安全级别约为 100 位（而非设计的 128 位），
//! 参见 <https://eprint.iacr.org/2016/1102.pdf>。
//! 在标准要求（如 SM9 GB/T 38635）的场景下可使用；
//! 对于更高安全要求建议迁移到 BLS12-381。

pub mod hash_to_curve;
pub mod threshold;

use crypto_bigint::{Zero, U256};
use rand_core::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::sm9::fields::fp::GROUP_ORDER;
use crate::sm9::fields::fp::{fn_from_bytes, Fn};
use crate::sm9::fields::fp12::{fp12_mul, fp12_to_bytes};
use crate::sm9::groups::g1::{G1Affine, G1Jacobian};
use crate::sm9::groups::g2::{G2Affine, G2Jacobian};
use crate::sm9::pairing::pairing;

use hash_to_curve::hash_to_g1;

// ── DST（域分离标签）─────────────────────────────────────────────────────────

/// 签名用 DST
pub const DST_SIGN: &[u8] = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";

/// Proof-of-Possession 用 DST（与签名 DST 不同，防止跨用途哈希碰撞）
pub const DST_POP: &[u8] = b"BLS_POP_SM9G1_XMD:SM3_SVDW_RO_POP_";

// ── 密钥类型 ──────────────────────────────────────────────────────────────────

/// BLS 私钥（标量，自动清零）
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsPrivKey {
    scalar: [u8; 32],
}

/// BLS 公钥（G2 点）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlsPubKey {
    /// G2 上的点（压缩格式：4||x_re||x_im||y_re||y_im，128 字节）
    point: G2Affine,
}

/// BLS 签名（G1 点）
#[derive(Clone, Copy, Debug)]
pub struct BlsSignature {
    point: G1Affine,
}

/// BLS 密钥份额（用于门限签名）
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlsKeyShare {
    /// 参与者索引（1-indexed）
    pub index: usize,
    /// 私钥份额（标量）
    scalar: [u8; 32],
}

impl BlsKeyShare {
    /// 获取此份额的公钥
    pub fn pub_key(&self) -> BlsPubKey {
        let sk = fn_from_bytes(&self.scalar);
        let sk_u256 = sk.retrieve();
        let p2 = G2Jacobian::from_affine(&G2Affine::generator());
        let pk_jac = G2Jacobian::scalar_mul(&sk_u256, &p2);
        BlsPubKey {
            point: pk_jac
                .to_affine()
                .expect("BlsKeyShare: 密钥份额不应产生无穷远点"),
        }
    }
}

// ── 密钥生成 ──────────────────────────────────────────────────────────────────

/// 生成 BLS 密钥对
///
/// # 参数
/// - `rng`：随机数生成器
///
/// # 返回
/// `(私钥, 公钥)` 对
pub fn bls_keygen<R: RngCore>(rng: &mut R) -> (BlsPrivKey, BlsPubKey) {
    loop {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar);
        // 确保标量 < 群阶 n 且非零
        let s = U256::from_be_slice(&scalar);
        if s.is_zero().into() || s >= GROUP_ORDER {
            continue;
        }
        let sk = BlsPrivKey { scalar };
        let pk = bls_public_key(&sk);
        return (sk, pk);
    }
}

/// 从私钥派生公钥
pub fn bls_public_key(sk: &BlsPrivKey) -> BlsPubKey {
    let s = fn_from_bytes(&sk.scalar);
    let s_u256 = s.retrieve();
    // pk = sk * P2（G2 基点）
    let p2 = G2Jacobian::from_affine(&G2Affine::generator());
    let pk_jac = G2Jacobian::scalar_mul(&s_u256, &p2);
    BlsPubKey {
        point: pk_jac
            .to_affine()
            .expect("bls_public_key: 私钥不应产生无穷远公钥"),
    }
}

// ── 签名与验签 ────────────────────────────────────────────────────────────────

/// BLS 签名
///
/// sigma = sk * H(msg)，其中 H 是 hash_to_g1。
/// 签名是确定性的（不需要随机数）。
///
/// # 错误
/// - `Error::ZeroScalar`：私钥为零
pub fn bls_sign(sk: &BlsPrivKey, msg: &[u8]) -> Result<BlsSignature, Error> {
    let s = fn_from_bytes(&sk.scalar);
    if s == Fn::ZERO {
        return Err(Error::ZeroScalar);
    }
    // Q = H(msg)（hash-to-G1）
    let q_jac = hash_to_g1(msg, DST_SIGN);
    // sigma = sk * Q
    let sigma_jac = G1Jacobian::scalar_mul(&s.retrieve(), &q_jac);
    let sigma = sigma_jac.to_affine().map_err(|_| Error::ZeroScalar)?;
    Ok(BlsSignature { point: sigma })
}

/// BLS 验签
///
/// 验证 e(sigma, P2) == e(H(msg), pk)。
///
/// # 错误
/// - `Error::VerifyFailed`：签名无效
pub fn bls_verify(pk: &BlsPubKey, msg: &[u8], sig: &BlsSignature) -> Result<(), Error> {
    // Q = H(msg)
    let q_jac = hash_to_g1(msg, DST_SIGN);
    let q = q_jac.to_affine().map_err(|_| Error::InvalidSignature)?;

    // lhs = e(sigma, P2)
    let p2 = G2Affine::generator();
    let lhs = pairing(&sig.point, &p2);

    // rhs = e(Q, pk)
    let rhs = pairing(&q, &pk.point);

    // 常量时间比较 GT 元素
    // Reason: 直接比较 Fp12 可能泄露时间信息，使用字节级常量时间比较
    let lhs_bytes = fp12_to_bytes(&lhs);
    let rhs_bytes = fp12_to_bytes(&rhs);
    if bool::from(lhs_bytes.ct_eq(&rhs_bytes)) {
        Ok(())
    } else {
        Err(Error::VerifyFailed)
    }
}

// ── 签名聚合 ──────────────────────────────────────────────────────────────────

/// 聚合多个 BLS 签名（G1 点加法）
///
/// # 错误
/// - `Error::InvalidInput`：签名列表为空
pub fn bls_aggregate(sigs: &[BlsSignature]) -> Result<BlsSignature, Error> {
    if sigs.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut agg = G1Jacobian::from_affine(&sigs[0].point);
    for sig in &sigs[1..] {
        agg = G1Jacobian::add(&agg, &G1Jacobian::from_affine(&sig.point));
    }
    let point = agg.to_affine().map_err(|_| Error::InvalidInput)?;
    Ok(BlsSignature { point })
}

/// 聚合验签（不同消息）
///
/// 验证 e(agg_sig, P2) == ∏ e(H(msg_i), pk_i)。
///
/// # 注意
/// 每个 (pk_i, msg_i) 对的消息不同时适用。
/// 若消息相同，使用 `bls_fast_aggregate_verify`。
///
/// # 错误
/// - `Error::InvalidInput`：公钥/消息列表为空或长度不匹配
/// - `Error::VerifyFailed`：验证失败
pub fn bls_aggregate_verify(
    pks: &[BlsPubKey],
    msgs: &[&[u8]],
    agg_sig: &BlsSignature,
) -> Result<(), Error> {
    if pks.is_empty() || pks.len() != msgs.len() {
        return Err(Error::InvalidInput);
    }

    // lhs = e(agg_sig, P2)
    let p2 = G2Affine::generator();
    let lhs = pairing(&agg_sig.point, &p2);

    // rhs = ∏ e(H(msg_i), pk_i)
    let q0 = hash_to_g1(msgs[0], DST_SIGN)
        .to_affine()
        .map_err(|_| Error::InvalidInput)?;
    let mut rhs = pairing(&q0, &pks[0].point);

    for (pk, msg) in pks[1..].iter().zip(msgs[1..].iter()) {
        let q = hash_to_g1(msg, DST_SIGN)
            .to_affine()
            .map_err(|_| Error::InvalidInput)?;
        let e_i = pairing(&q, &pk.point);
        rhs = fp12_mul(&rhs, &e_i);
    }

    let lhs_bytes = fp12_to_bytes(&lhs);
    let rhs_bytes = fp12_to_bytes(&rhs);
    if bool::from(lhs_bytes.ct_eq(&rhs_bytes)) {
        Ok(())
    } else {
        Err(Error::VerifyFailed)
    }
}

/// 快速聚合验签（相同消息）
///
/// 验证 e(agg_sig, P2) == e(H(msg), agg_pk)，其中 agg_pk = Σ pk_i。
///
/// # 错误
/// - `Error::InvalidInput`：公钥列表为空
/// - `Error::VerifyFailed`：验证失败
pub fn bls_fast_aggregate_verify(
    pks: &[BlsPubKey],
    msg: &[u8],
    agg_sig: &BlsSignature,
) -> Result<(), Error> {
    if pks.is_empty() {
        return Err(Error::InvalidInput);
    }

    // agg_pk = Σ pk_i（G2 点加法）
    let mut agg_pk = G2Jacobian::from_affine(&pks[0].point);
    for pk in &pks[1..] {
        agg_pk = G2Jacobian::add_jac(&agg_pk, &G2Jacobian::from_affine(&pk.point));
    }
    let agg_pk_affine = agg_pk.to_affine().map_err(|_| Error::InvalidInput)?;
    let agg_pk_pub = BlsPubKey {
        point: agg_pk_affine,
    };

    bls_verify(&agg_pk_pub, msg, agg_sig)
}

// ── 序列化 ────────────────────────────────────────────────────────────────────

impl BlsSignature {
    /// 序列化为 65 字节（未压缩 G1 点：0x04 || x || y）
    pub fn to_bytes(&self) -> [u8; 65] {
        self.point.to_bytes()
    }

    /// 从 65 字节反序列化
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, Error> {
        let point = G1Affine::from_bytes(bytes)?;
        Ok(BlsSignature { point })
    }
}

impl BlsPubKey {
    /// 序列化为 128 字节（G2 点：x_re || x_im || y_re || y_im）
    pub fn to_bytes(&self) -> [u8; 128] {
        self.point.to_bytes()
    }

    /// 从 128 字节反序列化
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let point = G2Affine::from_bytes(bytes)?;
        Ok(BlsPubKey { point })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_bls_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = bls_keygen(&mut rng);
        let msg = b"hello bls";
        let sig = bls_sign(&sk, msg).expect("签名应成功");
        bls_verify(&pk, msg, &sig).expect("验签应成功");
    }

    #[test]
    fn test_bls_verify_wrong_msg_fails() {
        let mut rng = OsRng;
        let (sk, pk) = bls_keygen(&mut rng);
        let sig = bls_sign(&sk, b"msg1").expect("签名应成功");
        assert!(
            bls_verify(&pk, b"msg2", &sig).is_err(),
            "错误消息应验签失败"
        );
    }

    #[test]
    fn test_bls_verify_wrong_key_fails() {
        let mut rng = OsRng;
        let (sk1, _pk1) = bls_keygen(&mut rng);
        let (_sk2, pk2) = bls_keygen(&mut rng);
        let msg = b"hello";
        let sig = bls_sign(&sk1, msg).expect("签名应成功");
        assert!(bls_verify(&pk2, msg, &sig).is_err(), "错误公钥应验签失败");
    }

    #[test]
    fn test_bls_aggregate_verify() {
        let mut rng = OsRng;
        let (sk1, pk1) = bls_keygen(&mut rng);
        let (sk2, pk2) = bls_keygen(&mut rng);
        let msg1 = b"message1";
        let msg2 = b"message2";
        let sig1 = bls_sign(&sk1, msg1).expect("签名1应成功");
        let sig2 = bls_sign(&sk2, msg2).expect("签名2应成功");
        let agg = bls_aggregate(&[sig1, sig2]).expect("聚合应成功");
        bls_aggregate_verify(&[pk1, pk2], &[msg1.as_ref(), msg2.as_ref()], &agg)
            .expect("聚合验签应成功");
    }

    #[test]
    fn test_bls_fast_aggregate_verify() {
        let mut rng = OsRng;
        let (sk1, pk1) = bls_keygen(&mut rng);
        let (sk2, pk2) = bls_keygen(&mut rng);
        let msg = b"shared message";
        let sig1 = bls_sign(&sk1, msg).expect("签名1应成功");
        let sig2 = bls_sign(&sk2, msg).expect("签名2应成功");
        let agg = bls_aggregate(&[sig1, sig2]).expect("聚合应成功");
        bls_fast_aggregate_verify(&[pk1, pk2], msg, &agg).expect("快速聚合验签应成功");
    }

    #[test]
    fn test_bls_signature_serialization() {
        let mut rng = OsRng;
        let (sk, _pk) = bls_keygen(&mut rng);
        let sig = bls_sign(&sk, b"test").expect("签名应成功");
        let bytes = sig.to_bytes();
        let sig2 = BlsSignature::from_bytes(&bytes).expect("反序列化应成功");
        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }
}
