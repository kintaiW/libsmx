//! SM2 椭圆曲线公钥密码算法（GB/T 32918.1-5-2016）
//!
//! 本 crate 提供符合 GB/T 32918-2016 的纯 Rust、`no_std` 实现：
//!
//! - **密钥生成**：[`generate_keypair`]
//! - **数字签名/验签**：[`SigningKey`] / [`VerifyingKey`]（实现 `signature::Signer/Verifier`）
//! - **公钥加密/解密**：[`encrypt`] / [`decrypt`]（需 `alloc` feature）
//! - **密钥交换**：[`key_exchange::ecdh`] / [`key_exchange::exchange_a`]
//! - **DER 编解码**：[`der`]
//!
//! ## 安全性声明
//!
//! - 所有私钥操作均为常量时间（Montgomery 域算术 + `subtle::ConditionallySelectable`）
//! - 私钥离开作用域后自动清零（[`ZeroizeOnDrop`]）
//! - 标量乘法固定迭代 256 位，不跳过前导零
//! - `sign_with_k` 危险接口需启用 `hazmat` feature
//!
//! ## 快速开始
//!
//! ```rust
//! use sm2::{SigningKey, VerifyingKey, DEFAULT_ID};
//! use sm2::signature::{Signer, Verifier};
//! use rand_core::OsRng;
//!
//! // 生成密钥对
//! let (pri, pub_bytes) = sm2::generate_keypair(&mut OsRng);
//! let signing   = SigningKey::new(pri, DEFAULT_ID);
//! let verifying = VerifyingKey::new(pub_bytes, DEFAULT_ID);
//!
//! // 签名
//! let msg = b"hello SM2";
//! let sig = signing.sign(msg);
//!
//! // 验签
//! verifying.verify(msg, &sig).expect("验签应通过");
//! ```
//!
//! ---
//!
//! SM2 elliptic curve public-key cryptography (GB/T 32918.1-5-2016).
//!
//! This crate provides a pure-Rust, `no_std` implementation of:
//!
//! - **Key generation**: [`generate_keypair`]
//! - **Signing / Verification**: [`SigningKey`] / [`VerifyingKey`]
//!   (implement `signature::Signer` / `Verifier`)
//! - **Public-key encryption / decryption**: [`encrypt`] / [`decrypt`]
//!   (requires `alloc` feature)
//! - **Key exchange**: [`key_exchange::ecdh`] / [`key_exchange::exchange_a`]
//! - **DER encoding / decoding**: [`der`]
//!
//! ## Security
//!
//! - All secret-dependent operations are constant-time
//! - Private keys are zeroized on drop ([`ZeroizeOnDrop`])
//! - Scalar multiplication iterates all 256 bits regardless of scalar value
//! - `sign_with_k` (dangerous raw-k API) requires the `hazmat` feature

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod der;
pub mod ec;
pub mod error;
pub mod field;
pub mod kdf;
pub mod key_exchange;
mod rfc6979;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crypto_bigint::{Zero, U256};
use rand_core::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use error::Error;
pub use signature;

use crate::ec::{multi_scalar_mul, AffinePoint, JacobianPoint};
use crate::field::{
    fn_add, fn_inv, fn_mul, fn_sub, fp_to_bytes, Fn, CURVE_A, CURVE_B, GROUP_ORDER,
    GROUP_ORDER_MINUS_1, GX, GY,
};

// ── 内部 SM3 包装 ─────────────────────────────────────────────────────────────

/// 内部轻量哈希上下文（包装 sm3::Sm3 的 Digest API）
///
/// Thin wrapper around `sm3::Sm3` exposing a streaming `update`/`finalize` API
/// identical to the original `Sm3Hasher`, so callers need no refactoring.
struct Sm3H(sm3::Sm3);

impl Sm3H {
    fn new() -> Self {
        use sm3::Digest;
        Sm3H(sm3::Sm3::new())
    }
    fn update(&mut self, data: &[u8]) {
        use sm3::Digest;
        self.0.update(data);
    }
    fn finalize(self) -> [u8; 32] {
        use sm3::Digest;
        self.0.finalize().into()
    }
}

// ── 常量 ──────────────────────────────────────────────────────────────────────

/// SM2 默认用户可辨别标识（GB/T 32918.2-2016 §A.2 示例值）
///
/// Default user distinguishable identifier (example from GB/T 32918.2-2016 §A.2).
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

// ── 私钥类型 ──────────────────────────────────────────────────────────────────

/// SM2 私钥（32 字节，离开作用域自动清零）
///
/// SM2 private key (32 bytes). Automatically zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

impl PrivateKey {
    /// 从字节构造私钥（验证 d ∈ [1, n-2]）
    ///
    /// Construct from bytes, validating d ∈ [1, n-2].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let d = U256::from_be_slice(bytes);
        if bool::from(d.is_zero()) || d >= GROUP_ORDER_MINUS_1 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(PrivateKey { bytes: *bytes })
    }

    /// 以字节引用访问私钥
    ///
    /// Access the private key bytes by reference.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// 计算对应公钥（65 字节，04||x||y）
    ///
    /// Derive the corresponding public key (65 bytes, uncompressed: 04||x||y).
    pub fn public_key(&self) -> [u8; 65] {
        let d = U256::from_be_slice(&self.bytes);
        let pub_jac = JacobianPoint::scalar_mul_g(&d);
        // Reason: 私钥合法性已在构造时验证，scalar_mul_g 结果不会是无穷远点
        let pub_aff = pub_jac
            .to_affine()
            .expect("valid private key produces valid public key");
        pub_aff.to_bytes()
    }
}

// ── 密钥生成 ──────────────────────────────────────────────────────────────────

/// 生成 SM2 密钥对（私钥 + 公钥 65 字节）
///
/// Generate a SM2 key pair (private key + 65-byte public key).
/// Conforms to GB/T 32918.1-2016 §6.1.
pub fn generate_keypair<R: RngCore>(rng: &mut R) -> (PrivateKey, [u8; 65]) {
    loop {
        let mut d_bytes = [0u8; 32];
        rng.fill_bytes(&mut d_bytes);
        let d = U256::from_be_slice(&d_bytes);
        if bool::from(d.is_zero()) || d >= GROUP_ORDER_MINUS_1 {
            d_bytes.zeroize();
            continue;
        }
        // Reason: 私钥满足范围约束，不会失败
        let priv_key = PrivateKey { bytes: d_bytes };
        let pub_key = priv_key.public_key();
        return (priv_key, pub_key);
    }
}

// ── Z 值计算（GB/T 32918.2-2016 §5.5）────────────────────────────────────────

/// 计算用户标识的 Z 值
///
/// Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)
///
/// Compute Z-value for the user identity. Conforms to GB/T 32918.2-2016 §5.5.
pub fn get_z(id: &[u8], pub_key: &[u8; 65]) -> [u8; 32] {
    let entl = (id.len() * 8) as u16;
    let mut h = Sm3H::new();
    h.update(&entl.to_be_bytes());
    h.update(id);
    h.update(&fp_to_bytes(&CURVE_A));
    h.update(&fp_to_bytes(&CURVE_B));
    h.update(&fp_to_bytes(&GX));
    h.update(&fp_to_bytes(&GY));
    h.update(&pub_key[1..33]); // Px
    h.update(&pub_key[33..65]); // Py
    h.finalize()
}

/// 计算消息摘要 e = SM3(Z || M)
///
/// Compute message digest e = SM3(Z || M). Conforms to GB/T 32918.2-2016 §5.5.
pub fn get_e(z: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = Sm3H::new();
    h.update(z);
    h.update(msg);
    h.finalize()
}

// ── 数字签名（GB/T 32918.2-2016 §6.2）───────────────────────────────────────

/// SM2 签名（使用指定随机数 k）
///
/// Sign using a specified nonce k. **Only expose under `hazmat` feature — misusing k leaks the private key.**
///
/// Sign with a fixed nonce k (for test vectors / hazmat use only).
/// Requires the `hazmat` feature gate.
#[cfg(feature = "hazmat")]
pub fn sign_with_k(e: &[u8; 32], pri_key: &PrivateKey, k: &U256) -> Result<[u8; 64], Error> {
    sign_with_k_inner(e, pri_key, k)
}

/// 内部签名实现（供 `sign` 和 `hazmat::sign_with_k` 共用）
fn sign_with_k_inner(e: &[u8; 32], pri_key: &PrivateKey, k: &U256) -> Result<[u8; 64], Error> {
    let d = U256::from_be_slice(pri_key.as_bytes());

    let kg_aff = JacobianPoint::scalar_mul_g(k)
        .to_affine()
        .map_err(|_| Error::InvalidSignature)?;
    let x1 = fp_to_bytes(&kg_aff.x);

    let e_val = U256::from_be_slice(e);
    let x1_val = U256::from_be_slice(&x1);
    let r_fn = fn_add(&Fn::new(&e_val), &Fn::new(&x1_val));
    let r = r_fn.retrieve();

    if bool::from(r.is_zero()) {
        return Err(Error::InvalidSignature);
    }
    if fn_add(&r_fn, &Fn::new(k)).retrieve().is_zero().into() {
        return Err(Error::InvalidSignature);
    }

    let d_fn = Fn::new(&d);
    let one_plus_d = fn_add(&Fn::ONE, &d_fn);
    let inv = fn_inv(&one_plus_d).ok_or(Error::InvalidPrivateKey)?;
    let rd = fn_mul(&r_fn, &d_fn);
    let s_fn = fn_mul(&inv, &fn_sub(&Fn::new(k), &rd));
    let s = s_fn.retrieve();

    if bool::from(s.is_zero()) {
        return Err(Error::InvalidSignature);
    }

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_be_bytes());
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(sig)
}

/// SM2 签名（随机 k，标准接口）
///
/// Sign with random nonce k. Accepts pre-computed digest `e = SM3(Z||M)`.
pub fn sign<R: RngCore>(e: &[u8; 32], pri_key: &PrivateKey, rng: &mut R) -> [u8; 64] {
    loop {
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);
        k_bytes.zeroize();
        if bool::from(k.is_zero()) || k >= GROUP_ORDER {
            continue;
        }
        if let Ok(sig) = sign_with_k_inner(e, pri_key, &k) {
            return sig;
        }
    }
}

/// SM2 确定性签名（RFC 6979，使用 HMAC-SM3 生成 k）
///
/// Sign with deterministic nonce k derived via RFC 6979.
/// Accepts pre-computed digest `e = SM3(Z||M)`.
///
/// # 安全关键点
///
/// 此函数不依赖外部 RNG，消除了 RNG 故障或偏差导致私钥泄露的风险。
/// 对于相同的 (私钥, 消息摘要) 对，签名结果完全确定。
pub fn sign_deterministic(e: &[u8; 32], pri_key: &PrivateKey) -> [u8; 64] {
    // Reason: RFC 6979 保证生成的 k 总是满足 0 < k < n，
    // 并且对于合法私钥，sign_with_k_inner 总会成功（极罕见的 r=0/s=0 情况由 RFC 6979 循环避免）。
    // 如果 sign_with_k_inner 失败（理论上极罕见），我们使用不同输入再试。
    let k = rfc6979::generate_k(pri_key.as_bytes(), e);
    // RFC 6979 生成的 k 在几乎所有情况下都有效，直接调用
    if let Ok(sig) = sign_with_k_inner(e, pri_key, &k) {
        return sig;
    }
    // 极罕见的 fallback：用 e+pri_key 的不同组合再生成一个 k
    // (实际上 RFC 6979 的循环设计保证不会到这里)
    let mut alt_input = [0u8; 32];
    for (i, (&a, &b)) in e.iter().zip(pri_key.as_bytes().iter()).enumerate() {
        alt_input[i] = a.wrapping_add(b).wrapping_add(1);
    }
    let k2 = rfc6979::generate_k(pri_key.as_bytes(), &alt_input);
    sign_with_k_inner(e, pri_key, &k2).expect("RFC 6979 fallback must succeed")
}

/// SM2 签名（便捷接口，自动计算 Z 值与消息摘要）
///
/// Convenience signing: auto-computes Z = SM3(ENTL||ID||...) and e = SM3(Z||M).
pub fn sign_message<R: RngCore>(
    msg: &[u8],
    id: &[u8],
    pri_key: &PrivateKey,
    rng: &mut R,
) -> [u8; 64] {
    let pub_key = pri_key.public_key();
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    sign(&e, pri_key, rng)
}

/// SM2 确定性签名便捷接口（RFC 6979，无需 RNG）
///
/// Convenience deterministic signing: auto-computes Z and e, then uses RFC 6979.
pub fn sign_message_deterministic(msg: &[u8], id: &[u8], pri_key: &PrivateKey) -> [u8; 64] {
    let pub_key = pri_key.public_key();
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);
    sign_deterministic(&e, pri_key)
}

// ── 签名验证（GB/T 32918.2-2016 §6.3）───────────────────────────────────────

/// SM2 验签
///
/// Verify a SM2 signature. Accepts pre-computed digest `e = SM3(Z||M)`.
pub fn verify(e: &[u8; 32], pub_key: &[u8; 65], sig: &[u8; 64]) -> Result<(), Error> {
    let r = U256::from_be_slice(&sig[..32]);
    let s = U256::from_be_slice(&sig[32..]);
    let n = GROUP_ORDER;

    if bool::from(r.is_zero()) || r >= n || bool::from(s.is_zero()) || s >= n {
        return Err(Error::InvalidSignature);
    }

    let t_fn = fn_add(&Fn::new(&r), &Fn::new(&s));
    let t = t_fn.retrieve();
    if bool::from(t.is_zero()) {
        return Err(Error::VerifyFailed);
    }

    let pa = AffinePoint::from_bytes(pub_key)?;
    let point = multi_scalar_mul(&s, &t, &pa)?;

    let e_val = U256::from_be_slice(e);
    let px_val = U256::from_be_slice(&fp_to_bytes(&point.x));
    let r_check = fn_add(&Fn::new(&e_val), &Fn::new(&px_val)).retrieve();

    // Reason: 常量时间比较，防时序侧信道
    if r.to_be_bytes().ct_eq(&r_check.to_be_bytes()).unwrap_u8() != 1 {
        return Err(Error::VerifyFailed);
    }
    Ok(())
}

/// SM2 验签（便捷接口，自动计算 Z 值与消息��要）
///
/// Convenience verification: auto-computes Z and e.
pub fn verify_message(
    msg: &[u8],
    id: &[u8],
    pub_key: &[u8; 65],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let z = get_z(id, pub_key);
    let e = get_e(&z, msg);
    verify(&e, pub_key, sig)
}

// ── 公钥加密（GB/T 32918.4-2016 §7.1）──────────────────────────────────────

/// SM2 公钥加密
///
/// SM2 public-key encryption. Output format: C1||C3||C2 (GB/T 32918.4-2016 §6.1).
/// Requires `alloc` feature.
#[cfg(feature = "alloc")]
pub fn encrypt<R: RngCore>(
    pub_key: &[u8; 65],
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let pa = AffinePoint::from_bytes(pub_key)?;

    loop {
        let mut k_bytes = [0u8; 32];
        rng.fill_bytes(&mut k_bytes);
        let k = U256::from_be_slice(&k_bytes);
        k_bytes.zeroize();
        if bool::from(k.is_zero()) || k >= GROUP_ORDER {
            continue;
        }

        let c1_aff = match JacobianPoint::scalar_mul_g(&k).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let c1 = c1_aff.to_bytes();

        let pa_jac = JacobianPoint::from_affine(&pa);
        let kpa_aff = match JacobianPoint::scalar_mul(&k, &pa_jac).to_affine() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let x2 = fp_to_bytes(&kpa_aff.x);
        let y2 = fp_to_bytes(&kpa_aff.y);

        let mut z_input = [0u8; 64];
        z_input[..32].copy_from_slice(&x2);
        z_input[32..].copy_from_slice(&y2);
        let t = kdf::kdf(&z_input, message.len());

        if t.iter().all(|&b| b == 0) {
            continue;
        }

        let c2: Vec<u8> = message.iter().zip(t.iter()).map(|(&m, &k)| m ^ k).collect();

        let mut h = Sm3H::new();
        h.update(&x2);
        h.update(message);
        h.update(&y2);
        let c3 = h.finalize();

        let mut output = Vec::with_capacity(65 + 32 + message.len());
        output.extend_from_slice(&c1);
        output.extend_from_slice(&c3);
        output.extend_from_slice(&c2);
        return Ok(output);
    }
}

// ── 公钥解密（GB/T 32918.4-2016 §7.2）──────────────────────────────────────

/// SM2 公钥解密（新格式 C1||C3||C2）
///
/// SM2 public-key decryption (format C1||C3||C2). Requires `alloc` feature.
#[cfg(feature = "alloc")]
pub fn decrypt(pri_key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 97 {
        return Err(Error::InvalidInputLength);
    }

    let d = U256::from_be_slice(pri_key.as_bytes());

    let c1_bytes: [u8; 65] = ciphertext[0..65].try_into().unwrap();
    let c1 = AffinePoint::from_bytes(&c1_bytes)?;
    let c3_expected: [u8; 32] = ciphertext[65..97].try_into().unwrap();
    let c2 = &ciphertext[97..];

    let c1_jac = JacobianPoint::from_affine(&c1);
    let dc1_aff = JacobianPoint::scalar_mul(&d, &c1_jac).to_affine()?;
    let x2 = fp_to_bytes(&dc1_aff.x);
    let y2 = fp_to_bytes(&dc1_aff.y);

    let mut z_input = [0u8; 64];
    z_input[..32].copy_from_slice(&x2);
    z_input[32..].copy_from_slice(&y2);
    let t = kdf::kdf(&z_input, c2.len());

    if t.iter().all(|&b| b == 0) {
        return Err(Error::DecryptFailed);
    }

    let m: Vec<u8> = c2.iter().zip(t.iter()).map(|(&c, &k)| c ^ k).collect();

    let mut h = Sm3H::new();
    h.update(&x2);
    h.update(&m);
    h.update(&y2);
    let c3_computed = h.finalize();

    // Reason: 先验证 C3 再返回明文，防止 chosen-ciphertext 攻击
    if c3_expected.ct_eq(&c3_computed).unwrap_u8() != 1 {
        return Err(Error::DecryptFailed);
    }
    Ok(m)
}

// ── signature::Signer / Verifier trait 实现 ──────────────────────────────────

/// SM2 签名结果（r||s，64 字节）
///
/// SM2 signature (r||s, 64 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sm2Signature {
    bytes: [u8; 64],
}

impl Sm2Signature {
    /// 从 64 字节原始 r||s 构造签名
    ///
    /// Construct from raw 64-byte r||s.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Sm2Signature { bytes }
    }

    /// 以字节切片返回签名
    ///
    /// Return the signature as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

impl AsRef<[u8]> for Sm2Signature {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ── SigningKey ────────────────────────────────────────────────────────────────

/// SM2 签名密钥（私钥 + 用户标识）
///
/// SM2 signing key: wraps a private key with a user identity string.
/// Implements [`signature::Signer<Sm2Signature>`].
pub struct SigningKey<'id> {
    private_key: PrivateKey,
    /// 用户可辨别标识 / User distinguishable identifier
    pub id: &'id [u8],
}

impl<'id> SigningKey<'id> {
    /// 构造签名密钥
    ///
    /// Construct a signing key from a private key and user ID.
    pub fn new(private_key: PrivateKey, id: &'id [u8]) -> Self {
        SigningKey { private_key, id }
    }

    /// 获取对应的公钥字节（65 字节，04||x||y）
    ///
    /// Derive the corresponding public key bytes (65 bytes, uncompressed).
    pub fn public_key_bytes(&self) -> [u8; 65] {
        self.private_key.public_key()
    }
}

impl<'id> signature::Signer<Sm2Signature> for SigningKey<'id> {
    fn try_sign(&self, msg: &[u8]) -> Result<Sm2Signature, signature::Error> {
        // Reason: sign_message 需要 RngCore；此处用 OsRng 退化实现
        // 在 no_std 环境中，若无 OsRng 可用，调用方应直接调用 sign/sign_message
        use rand_core::OsRng;
        let sig_bytes = sign_message(msg, self.id, &self.private_key, &mut OsRng);
        Ok(Sm2Signature { bytes: sig_bytes })
    }
}

// ── VerifyingKey ──────────────────────────────────────────────────────────────

/// SM2 验证密钥（公钥 + 用户标识）
///
/// SM2 verifying key: wraps a public key with a user identity string.
/// Implements [`signature::Verifier<Sm2Signature>`].
pub struct VerifyingKey<'id> {
    public_key: [u8; 65],
    /// 用户可辨别标识 / User distinguishable identifier
    pub id: &'id [u8],
}

impl<'id> VerifyingKey<'id> {
    /// 构造验证密钥
    ///
    /// Construct a verifying key from a public key and user ID.
    pub fn new(public_key: [u8; 65], id: &'id [u8]) -> Self {
        VerifyingKey { public_key, id }
    }

    /// 验证公钥是否在 SM2 曲线上
    ///
    /// Returns `Ok(())` if the public key is a valid SM2 curve point.
    pub fn validate(&self) -> Result<(), Error> {
        AffinePoint::from_bytes(&self.public_key).map(|_| ())
    }
}

impl<'id> signature::Verifier<Sm2Signature> for VerifyingKey<'id> {
    fn verify(&self, msg: &[u8], signature: &Sm2Signature) -> Result<(), signature::Error> {
        verify_message(msg, self.id, &self.public_key, &signature.bytes)
            .map_err(signature::Error::from)
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 共用测试私钥（来自 libsmx 内部测试）
    const D_BYTES: [u8; 32] = [
        0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3,
        0x9f, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef,
        0x4d, 0xf7, 0xc5, 0xb8,
    ];

    const K_BYTES: [u8; 32] = [
        0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a, 0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0,
        0x2d, 0xcc, 0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce, 0x6d, 0x54, 0xb8, 0x0d,
        0xea, 0xc1, 0xbc, 0x21,
    ];

    // 测试专用的确定性 RNG（使用固定字节池）
    struct FakeRng([u8; 32]);
    impl rand_core::RngCore for FakeRng {
        fn next_u32(&mut self) -> u32 { 0 }
        fn next_u64(&mut self) -> u64 { 0 }
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
    fn test_private_key_from_bytes_valid() {
        PrivateKey::from_bytes(&D_BYTES).expect("合法私钥应成功构造");
    }

    #[test]
    fn test_private_key_from_bytes_zero() {
        assert!(PrivateKey::from_bytes(&[0u8; 32]).is_err(), "全零私钥应拒绝");
    }

    #[test]
    fn test_public_key_on_curve() {
        let pri = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_bytes = pri.public_key();
        let point = AffinePoint::from_bytes(&pub_bytes).expect("公钥应在曲线上");
        assert!(point.is_on_curve());
    }

    #[test]
    fn test_get_z_deterministic() {
        let pub_key = [0x04u8; 65];
        let z1 = get_z(DEFAULT_ID, &pub_key);
        let z2 = get_z(DEFAULT_ID, &pub_key);
        assert_eq!(z1, z2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"hello sm2";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);

        let k = U256::from_be_slice(&K_BYTES);
        let sig = sign_with_k_inner(&e, &pri_key, &k).expect("签名应成功");
        verify(&e, &pub_key, &sig).expect("验签应通过");
    }

    #[test]
    fn test_sign_message_verify_message() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let mut rng = FakeRng(K_BYTES);

        let msg = b"hello sign_message";
        let sig = sign_message(msg, DEFAULT_ID, &pri_key, &mut rng);
        verify_message(msg, DEFAULT_ID, &pub_key, &sig).expect("便捷验签应通过");
    }

    #[test]
    fn test_verify_rejects_tampered_sig() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"hello sm2";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);
        let k = U256::from_be_slice(&K_BYTES);
        let mut sig = sign_with_k_inner(&e, &pri_key, &k).unwrap();
        sig[0] ^= 0x01;
        assert!(verify(&e, &pub_key, &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_id() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let mut rng = FakeRng(K_BYTES);
        let msg = b"hello sign_message";
        let sig = sign_message(msg, DEFAULT_ID, &pri_key, &mut rng);
        assert!(verify_message(msg, b"wrong-id", &pub_key, &sig).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"Hello, SM2 encryption!";
        let mut rng = FakeRng(K_BYTES);

        let ciphertext = encrypt(&pub_key, msg, &mut rng).expect("加密应成功");
        let plaintext = decrypt(&pri_key, &ciphertext).expect("解密应成功");
        assert_eq!(plaintext, msg);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_decrypt_rejects_tampered_ciphertext() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let mut rng = FakeRng(K_BYTES);
        let mut ct = encrypt(&pub_key, b"test", &mut rng).unwrap();
        ct[70] ^= 0xFF;
        assert!(decrypt(&pri_key, &ct).is_err());
    }

    // ── signature trait 测试 ────────────────────────────────────────────────

    #[test]
    fn test_signing_key_verifying_key_roundtrip() {
        use signature::{Signer, Verifier};

        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_bytes = pri_key.public_key();

        let signing   = SigningKey::new(pri_key, DEFAULT_ID);
        let verifying = VerifyingKey::new(pub_bytes, DEFAULT_ID);

        let msg = b"signature trait roundtrip";
        let sig = signing.sign(msg);
        verifying.verify(msg, &sig).expect("SigningKey/VerifyingKey 验签应通过");
    }

    #[test]
    fn test_verifying_key_validate() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_bytes = pri_key.public_key();
        let vk = VerifyingKey::new(pub_bytes, DEFAULT_ID);
        assert!(vk.validate().is_ok());
    }

    /// RFC 6979 确定性签名：结果可被 verify 通过
    #[test]
    fn test_sign_deterministic_verify() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"RFC 6979 deterministic test";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);

        let sig = sign_deterministic(&e, &pri_key);
        verify(&e, &pub_key, &sig).expect("deterministic sign must verify");
    }

    /// RFC 6979 确定性签名：相同输入总产生相同签名
    #[test]
    fn test_sign_deterministic_reproducible() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"reproducibility test";
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, msg);

        let sig1 = sign_deterministic(&e, &pri_key);
        let sig2 = sign_deterministic(&e, &pri_key);
        assert_eq!(sig1, sig2, "RFC 6979 signatures must be reproducible");
        verify(&e, &pub_key, &sig1).expect("must verify");
    }

    /// sign_message_deterministic 便捷接口
    #[test]
    fn test_sign_message_deterministic() {
        let pri_key = PrivateKey::from_bytes(&D_BYTES).unwrap();
        let pub_key = pri_key.public_key();
        let msg = b"sign_message_deterministic test";

        let sig = sign_message_deterministic(msg, DEFAULT_ID, &pri_key);
        verify_message(msg, DEFAULT_ID, &pub_key, &sig).expect("deterministic message sig must verify");
    }
}
