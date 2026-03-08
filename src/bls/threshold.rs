//! BLS 门限签名（Shamir 秘密分享 + Lagrange 插值）
//!
//! 实现 (t+1, n) 门限 BLS 签名：
//! - 可信分发者将私钥分割为 n 份，任意 t+1 份可重建签名
//! - 各参与者独立计算部分签名
//! - 聚合器组合 t+1 份部分签名得到完整 BLS 签名
//!
//! # 安全注意
//! 本实现采用 Trusted Dealer 模型：分发者可以知晓完整私钥。
//! 对于无可信第三方的场景，需使用 DKG（分布式密钥生成），超出当前范围。

extern crate alloc;
use alloc::vec::Vec;

use crypto_bigint::{Zero, U256};
use rand_core::RngCore;

use crate::error::Error;
use crate::sm9::fields::fp::{fn_from_bytes, fn_inv, fn_mul, fn_to_bytes, Fn, GROUP_ORDER};
use crate::sm9::groups::g1::G1Jacobian;

use super::{bls_sign, BlsKeyShare, BlsPrivKey, BlsSignature};

// ── Shamir 密钥分割 ──────────────────────────────────────────────────────────

/// 将 BLS 私钥分割为 n 份，需要 threshold+1 份才能组合签名
///
/// # 参数
/// - `sk`：主私钥
/// - `threshold`：门限值 t（需要 t+1 份参与者）
/// - `total`：总份额数 n（n >= t+1）
/// - `rng`：随机数生成器
///
/// # 返回
/// `(主公钥, Vec<BlsKeyShare>)` — n 份密钥份额
///
/// # 错误
/// - `Error::InvalidInput`：参数不合法（total < threshold+1，或 threshold=0）
pub fn bls_threshold_keygen<R: RngCore>(
    sk: &BlsPrivKey,
    threshold: usize,
    total: usize,
    rng: &mut R,
) -> Result<Vec<BlsKeyShare>, Error> {
    if total < threshold + 1 || threshold == 0 {
        return Err(Error::InvalidInput);
    }

    // 构造 threshold 次随机多项式 f(x) = sk + a1*x + ... + at*x^t （mod n）
    // f(0) = sk
    let sk_fn = fn_from_bytes(&sk.scalar);

    // 随机系数 a1..at
    let mut coeffs: Vec<Fn> = Vec::with_capacity(threshold + 1);
    coeffs.push(sk_fn);
    for _ in 0..threshold {
        let mut bytes = [0u8; 32];
        loop {
            rng.fill_bytes(&mut bytes);
            let v = U256::from_be_slice(&bytes);
            if !bool::from(v.is_zero()) && v < GROUP_ORDER {
                coeffs.push(fn_from_bytes(&bytes));
                break;
            }
        }
    }

    // 为每个参与者 i=1..=n 计算 f(i)
    let mut shares = Vec::with_capacity(total);
    for i in 1..=total {
        let i_fn = fn_from_bytes(&{
            let mut b = [0u8; 32];
            let i_u256 = U256::from(i as u64);
            b.copy_from_slice(&i_u256.to_be_bytes());
            b
        });

        // Horner 方法计算 f(i) = a0 + i*(a1 + i*(a2 + ... + i*at)...)
        let mut val = coeffs[threshold];
        for j in (0..threshold).rev() {
            val = fn_mul(&val, &i_fn);
            val = crate::sm9::fields::fp::fn_add(&val, &coeffs[j]);
        }

        shares.push(BlsKeyShare {
            index: i,
            scalar: fn_to_bytes(&val),
        });
    }

    // 清零多项式系数（防止内存残留）
    coeffs.fill(Fn::ZERO);

    Ok(shares)
}

// ── Lagrange 插值系数 ──────────────────────────────────────────────────────

/// 计算 Lagrange 系数 λᵢ（在 Fn 域上）
///
/// λᵢ = ∏_{j ∈ S, j≠i} (j / (j-i)) mod n
///
/// # 参数
/// - `i`：当前参与者索引（1-indexed）
/// - `participants`：参与的所有参与者索引集合
fn lagrange_coefficient(i: usize, participants: &[usize]) -> Fn {
    let _i_fn = index_to_fn(i);

    let mut num = Fn::ONE; // 分子 ∏ j
    let mut den = Fn::ONE; // 分母 ∏ (j-i)

    for &j in participants {
        if j != i {
            let j_fn = index_to_fn(j);
            num = fn_mul(&num, &j_fn);

            // diff = j - i（在 Fn 域上，若 j < i 则结果自动 mod n 为负数）
            let diff = if j > i {
                index_to_fn(j - i)
            } else {
                // i > j：diff = -(i-j)
                let pos = index_to_fn(i - j);
                crate::sm9::fields::fp::fn_neg(&pos)
            };
            den = fn_mul(&den, &diff);
        }
    }

    // λᵢ = num / den = num * den^{-1}
    let den_inv = fn_inv(&den).expect("Lagrange: 分母不应为零（参与者索引应互不相同）");
    fn_mul(&num, &den_inv)
}

/// 将 usize 索引转换为 Fn 元素
fn index_to_fn(i: usize) -> Fn {
    let mut b = [0u8; 32];
    let u = U256::from(i as u64);
    b.copy_from_slice(&u.to_be_bytes());
    fn_from_bytes(&b)
}

// ── 部分签名与组合 ─────────────────────────────────────────────────────────

/// 计算部分签名（与普通 BLS 签名相同，使用份额私钥）
///
/// sigma_i = sk_i * H(msg)
pub fn bls_partial_sign(share: &BlsKeyShare, msg: &[u8]) -> Result<BlsSignature, Error> {
    // 将份额包装为 BlsPrivKey 格式
    let sk = BlsPrivKey {
        scalar: share.scalar,
    };
    bls_sign(&sk, msg)
}

/// 组合 t+1 份部分签名得到完整 BLS 签名（Lagrange 插值）
///
/// sigma = Σ_{i ∈ S} λᵢ · sigma_i
///
/// # 参数
/// - `partial_sigs`：`(参与者索引, 部分签名)` 的列表，长度需 >= threshold+1
///
/// # 错误
/// - `Error::InvalidInput`：签名列表为空
/// - `Error::PointAtInfinity`：组合结果为无穷远点
pub fn bls_combine_signatures(
    partial_sigs: &[(usize, BlsSignature)],
) -> Result<BlsSignature, Error> {
    if partial_sigs.is_empty() {
        return Err(Error::InvalidInput);
    }

    let participants: Vec<usize> = partial_sigs.iter().map(|(i, _)| *i).collect();

    // sigma = Σ λᵢ * sigma_i
    let mut result = G1Jacobian::INFINITY;

    for (i, sig) in partial_sigs {
        let lambda = lagrange_coefficient(*i, &participants);
        let lambda_u256 = lambda.retrieve();
        // λᵢ * sigma_i（G1 标量乘）
        let sig_jac = G1Jacobian::from_affine(&sig.point);
        let scaled = G1Jacobian::scalar_mul(&lambda_u256, &sig_jac);
        result = G1Jacobian::add(&result, &scaled);
    }

    let point = result.to_affine().map_err(|_| Error::PointAtInfinity)?;
    Ok(BlsSignature { point })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{bls_keygen, bls_verify};
    use rand_core::OsRng;

    #[test]
    fn test_threshold_2_of_3() {
        let mut rng = OsRng;
        // 生成主密钥
        let (sk, pk) = bls_keygen(&mut rng);
        let msg = b"threshold test message";

        // 分割为 3 份，门限 2（需 3 份 = threshold+1=3）
        // 实际是 (threshold=2, total=3)，需要 3 份
        let shares = bls_threshold_keygen(&sk, 2, 3, &mut rng).expect("密钥分割应成功");
        assert_eq!(shares.len(), 3);

        // 使用全部 3 份计算部分签名（满足门限 t+1=3）
        let partial_sigs: Vec<(usize, BlsSignature)> = shares
            .iter()
            .map(|s| {
                let sig = bls_partial_sign(s, msg).expect("部分签名应成功");
                (s.index, sig)
            })
            .collect();

        // 组合签名
        let combined = bls_combine_signatures(&partial_sigs).expect("签名组合应成功");

        // 用主公钥验证
        bls_verify(&pk, msg, &combined).expect("门限签名验证应成功");
    }

    #[test]
    fn test_threshold_1_of_2() {
        let mut rng = OsRng;
        // threshold=1, total=2：需要 2 份
        let (sk, pk) = bls_keygen(&mut rng);
        let msg = b"simple threshold";

        let shares = bls_threshold_keygen(&sk, 1, 2, &mut rng).expect("密钥分割应成功");

        // 使用 2 份（threshold+1=2）
        let partial_sigs: Vec<(usize, BlsSignature)> = shares
            .iter()
            .map(|s| (s.index, bls_partial_sign(s, msg).unwrap()))
            .collect();

        let combined = bls_combine_signatures(&partial_sigs).unwrap();
        bls_verify(&pk, msg, &combined).expect("(1,2) 门限签名验证应成功");
    }

    #[test]
    fn test_invalid_threshold_params() {
        let mut rng = OsRng;
        let (sk, _pk) = bls_keygen(&mut rng);
        // total < threshold+1
        assert!(bls_threshold_keygen(&sk, 3, 2, &mut rng).is_err());
        // threshold = 0
        assert!(bls_threshold_keygen(&sk, 0, 3, &mut rng).is_err());
    }
}
