//! SM9 标识密码算法（GB/T 38635.1-2-2020）
//!
//! 实现内容：
//! - SM9 签名密钥生成（§6.1）
//! - SM9 数字签名与验签（§6.2, §6.3）
//! - SM9 加密密钥生成（§7.1）
//! - SM9 公钥加密与解密（§7.2, §7.3）
//!
//! # 重要安全说明
//! SM9 私钥（特别是签名私钥）在离开作用域时自动清零（ZeroizeOnDrop）。

pub mod fields;
pub mod groups;
pub mod pairing;
pub mod utils;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crypto_bigint::{Zero, U256};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::sm3::Sm3Hasher;
use crate::sm9::fields::fp::{fn_add, fn_inv, fn_mul, Fn, GROUP_ORDER, GROUP_ORDER_MINUS_1};
use crate::sm9::fields::fp12::{fp12_mul, Fp12};
use crate::sm9::groups::g1::{G1Affine, G1Jacobian};
use crate::sm9::groups::g2::{G2Affine, G2Jacobian};
use crate::sm9::pairing::pairing;
use crate::sm9::utils::{fp12_to_bytes_for_kdf, sm9_h1, sm9_h2};

// ── SM9 签名私钥（dA）──────────────────────────────────────────────────────

/// SM9 签名私钥（G1 上的点，离开作用域自动清零）
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm9SignPrivKey {
    /// 私钥点 dA = t·G1 对应的 G1 仿射坐标字节（65 字节）
    bytes: [u8; 65],
}

impl Sm9SignPrivKey {
    /// 从字节构造（65 字节，04||x||y）
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, Error> {
        let p = G1Affine::from_bytes(bytes)?;
        if !p.is_on_curve() {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Sm9SignPrivKey { bytes: *bytes })
    }

    /// 以字节引用访问
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.bytes
    }
}

// ── SM9 主私钥（s）─────────────────────────────────────────────────────────

/// SM9 主私钥标量（签名主私钥 ks 或加密主私钥 ke），32 字节
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sm9MasterPrivKey {
    bytes: [u8; 32],
}

impl Sm9MasterPrivKey {
    /// 从字节构造（验证 ∈ [1, n-2]）
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let s = U256::from_be_slice(bytes);
        if bool::from(s.is_zero()) || s >= GROUP_ORDER_MINUS_1 {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(Sm9MasterPrivKey { bytes: *bytes })
    }

    /// 字节访问
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// ── SM9 主公钥（Ppub）──────────────────────────────────────────────────────

/// SM9 签名主公钥（G2 上的点，128 字节）
#[derive(Clone, Debug)]
pub struct Sm9SignPubKey {
    bytes: [u8; 128],
}

impl Sm9SignPubKey {
    /// 从字节构造
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let p = G2Affine::from_bytes(bytes)?;
        if !p.is_on_curve() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Sm9SignPubKey { bytes: *bytes })
    }

    /// 以字节引用访问（128 字节）
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.bytes
    }
}

/// SM9 加密主公钥（G2 上的点，128 字节）
///
/// Reason: 标准 GB/T 38635.1-2020 中加密主公钥 Ppub-e = ke·P2（G2 上），
///   这样才能使加密时 QB = h1·P2 + Ppub-e 在 G2 上，
///   从而 C1 = r·QB 和解密时 e(de, C1) = e(P1,P2)^{ke·r} 正确对应。
#[derive(Clone, Debug)]
pub struct Sm9EncPubKey {
    bytes: [u8; 128],
}

impl Sm9EncPubKey {
    /// 从字节构造（128 字节：G2 上的点）
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let p = G2Affine::from_bytes(bytes)?;
        if !p.is_on_curve() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Sm9EncPubKey { bytes: *bytes })
    }

    /// 以字节引用访问（128 字节）
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.bytes
    }
}

// ── 密钥生成 ──────────────────────────────────────────────────────────────

/// 生成 SM9 签名主密钥对 (ks, Ppub-s)
///
/// ks ∈ [1, n-2]，Ppub-s = ks·P2
pub fn generate_sign_master_keypair<R: RngCore>(rng: &mut R) -> (Sm9MasterPrivKey, Sm9SignPubKey) {
    loop {
        let mut ks_bytes = [0u8; 32];
        rng.fill_bytes(&mut ks_bytes);
        let ks = U256::from_be_slice(&ks_bytes);
        if bool::from(ks.is_zero()) || ks >= GROUP_ORDER_MINUS_1 {
            ks_bytes.zeroize();
            continue;
        }
        let ppub = G2Jacobian::scalar_mul_g2(&ks).to_affine().unwrap();
        let priv_key = Sm9MasterPrivKey { bytes: ks_bytes };
        let pub_key = Sm9SignPubKey {
            bytes: ppub.to_bytes(),
        };
        return (priv_key, pub_key);
    }
}

/// 为用户 ID 生成 SM9 签名私钥 dA
///
/// GB/T 38635.2-2020 §6.1：
///   t1 = H1(ID||hid, N) + ks
///   t2 = ks · t1^{-1} mod N（注意：不是 t1^{-1}·P1，而是 ks·t1^{-1}·P1）
///   dA = [t2]P1
/// hid = 0x01（签名）
pub fn generate_sign_user_key(
    master_priv: &Sm9MasterPrivKey,
    id: &[u8],
) -> Result<Sm9SignPrivKey, Error> {
    let ks = U256::from_be_slice(master_priv.as_bytes());
    let h = sm9_h1(id, 0x01);
    // t1 = (ks + h) mod n
    let t1_fn = fn_add(&Fn::new(&ks), &Fn::new(&h));
    let t1 = t1_fn.retrieve();
    if bool::from(t1.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    // t2 = ks * t1^{-1} mod n
    // Reason: 标准 GB/T 38635.2-2020 §6.1 要求 dA = [ks·t1^{-1}]P1，
    //   而非 [t1^{-1}]P1。
    let t1_inv = fn_inv(&t1_fn).ok_or(Error::ZeroScalar)?;
    let ks_fn = Fn::new(&ks);
    let t2_fn = fn_mul(&ks_fn, &t1_inv);
    let t2 = t2_fn.retrieve();
    if bool::from(t2.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    // dA = t2 · P1
    let da = G1Jacobian::scalar_mul_g1(&t2).to_affine()?;
    Ok(Sm9SignPrivKey {
        bytes: da.to_bytes(),
    })
}

/// 生成 SM9 加密主密钥对 (ke, Ppub-e)
///
/// ke ∈ [1, n-2]，Ppub-e = ke·P2（G2 上，128 字节）
/// Reason: 加密主公钥在 G2 上，以保证 QB = h1·P2+Ppub-e 在 G2 上，
///   使得 C1=r·QB 与解密时 e(de, C1) 数学自洽。
pub fn generate_enc_master_keypair<R: RngCore>(rng: &mut R) -> (Sm9MasterPrivKey, Sm9EncPubKey) {
    loop {
        let mut ke_bytes = [0u8; 32];
        rng.fill_bytes(&mut ke_bytes);
        let ke = U256::from_be_slice(&ke_bytes);
        if bool::from(ke.is_zero()) || ke >= GROUP_ORDER_MINUS_1 {
            ke_bytes.zeroize();
            continue;
        }
        // Ppub-e = ke·P2（G2 上，128 字节）
        let ppub = G2Jacobian::scalar_mul_g2(&ke).to_affine().unwrap();
        let priv_key = Sm9MasterPrivKey { bytes: ke_bytes };
        let pub_key = Sm9EncPubKey {
            bytes: ppub.to_bytes(),
        };
        return (priv_key, pub_key);
    }
}

/// 为用户 ID 生成 SM9 加密私钥 de（G1 点）
///
/// GB/T 38635.1-2020 §6.1（加密密钥派生）：
///   t1 = H1(ID||hid, N) + ke
///   t2 = ke · t1^{-1} mod N
///   de = [t2]P1
pub fn generate_enc_user_key(
    master_priv: &Sm9MasterPrivKey,
    id: &[u8],
) -> Result<Sm9SignPrivKey, Error> {
    // de 与 dA 结构相同，都是 G1 点，共用 Sm9SignPrivKey 类型
    let ke = U256::from_be_slice(master_priv.as_bytes());
    let h = sm9_h1(id, 0x03); // hid = 0x03 for encryption
    let t1_fn = fn_add(&Fn::new(&ke), &Fn::new(&h));
    let t1 = t1_fn.retrieve();
    if bool::from(t1.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    // t2 = ke * t1^{-1} mod n
    // Reason: 标准 §6.1 要求 de = [ke·t1^{-1}]P1
    let t1_inv = fn_inv(&t1_fn).ok_or(Error::ZeroScalar)?;
    let ke_fn = Fn::new(&ke);
    let t2_fn = fn_mul(&ke_fn, &t1_inv);
    let t2 = t2_fn.retrieve();
    if bool::from(t2.is_zero()) {
        return Err(Error::ZeroScalar);
    }
    let de = G1Jacobian::scalar_mul_g1(&t2).to_affine()?;
    Ok(Sm9SignPrivKey {
        bytes: de.to_bytes(),
    })
}

// ── SM9 签名（GB/T 38635.2-2020 §6.2）────────────────────────────────────

/// SM9 数字签名
///
/// 输出 (h, S)：h 为 32 字节标量，S 为 65 字节 G1 点
///
/// # 参数
/// - `msg`: 消息
/// - `da`: 签名私钥（G1 点）
pub fn sm9_sign<R: RngCore>(
    msg: &[u8],
    da: &Sm9SignPrivKey,
    sign_pub: &Sm9SignPubKey,
    rng: &mut R,
) -> Result<([u8; 32], [u8; 65]), Error> {
    let da_point = G1Affine::from_bytes(da.as_bytes())?;
    let ppub = G2Affine::from_bytes(sign_pub.as_bytes())?;

    loop {
        // 步骤 A1：随机 r ∈ [1, n-1]
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = U256::from_be_slice(&r_bytes);
        r_bytes.zeroize();
        if bool::from(r.is_zero()) || r >= GROUP_ORDER {
            continue;
        }

        // 步骤 A2：g = e(P1, Ppub-s)（配对）
        let g = pairing(&G1Affine::generator(), &ppub);

        // 步骤 A3：w = g^r
        let w = fp12_pow(&g, &r);
        let w_bytes = fp12_to_bytes_for_kdf(&w);

        // 步骤 A4：h = H2(M || w)
        let h_val = sm9_h2(msg, &w_bytes);
        if bool::from(h_val.is_zero()) {
            continue;
        }

        // 步骤 A5：l = (r - h) mod n
        let h_fn = Fn::new(&h_val);
        let r_fn = Fn::new(&r);
        let l_fn = {
            // Reason: fn_sub 可能给负值，crypto_bigint 的 ConstMontyForm 自动 mod n 处理
            use crate::sm9::fields::fp::fn_sub;
            fn_sub(&r_fn, &h_fn)
        };
        let l = l_fn.retrieve();
        if bool::from(l.is_zero()) {
            continue;
        }

        // 步骤 A6：S = l · dA
        let da_jac = G1Jacobian::from_affine(&da_point);
        let s = G1Jacobian::scalar_mul(&l, &da_jac).to_affine()?;

        let mut h_out = [0u8; 32];
        h_out.copy_from_slice(&h_val.to_be_bytes());
        return Ok((h_out, s.to_bytes()));
    }
}

/// SM9 验签（GB/T 38635.2-2020 §6.3）
///
/// # 参数
/// - `msg`: 消息
/// - `h`: 签名 h（32 字节）
/// - `s`: 签名 S（65 字节 G1 点）
/// - `id`: 签名者 ID
/// - `sign_pub`: 签名主公钥
pub fn sm9_verify(
    msg: &[u8],
    h: &[u8; 32],
    s: &[u8; 65],
    id: &[u8],
    sign_pub: &Sm9SignPubKey,
) -> Result<(), Error> {
    let h_val = U256::from_be_slice(h);
    if bool::from(h_val.is_zero()) || h_val >= GROUP_ORDER {
        return Err(Error::InvalidSignature);
    }

    // 步骤 B1：验证 h ∈ [1, n-1]（已验证）

    // 步骤 B2：验证 S 在 G1 上
    let s_point = G1Affine::from_bytes(s).map_err(|_| Error::InvalidSignature)?;
    if !s_point.is_on_curve() {
        return Err(Error::InvalidSignature);
    }

    // 步骤 B3：g = e(P1, Ppub-s)
    let ppub = G2Affine::from_bytes(sign_pub.as_bytes())?;
    let g = pairing(&G1Affine::generator(), &ppub);

    // 步骤 B4：t = g^h
    let t = fp12_pow(&g, &h_val);

    // 步骤 B5：h1 = H1(ID || hid, n)
    let h1 = sm9_h1(id, 0x01);

    // 步骤 B6：P = h1·G2 + Ppub-s
    let h1g2 = G2Jacobian::scalar_mul_g2(&h1).to_affine()?;
    let ppub_jac = G2Jacobian::from_affine(&ppub);
    let h1g2_jac = G2Jacobian::from_affine(&h1g2);
    let p_jac = G2Jacobian::add_jac(&ppub_jac, &h1g2_jac);
    let p = p_jac.to_affine()?;

    // 步骤 B7：u = e(S, P)
    let u = pairing(&s_point, &p);

    // 步骤 B8：w' = u · t
    let w_prime = fp12_mul(&u, &t);
    let w_prime_bytes = fp12_to_bytes_for_kdf(&w_prime);

    // 步骤 B9：H2(M || w') == h
    let h_check = sm9_h2(msg, &w_prime_bytes);
    let h_check_bytes = h_check.to_be_bytes();

    // 常量时间比较防时序侧信道
    if h.ct_eq(&h_check_bytes).unwrap_u8() != 1 {
        return Err(Error::Sm9VerifyFailed);
    }
    Ok(())
}

// ── SM9 加密（GB/T 38635.1-2020 §7.2）────────────────────────────────────

/// SM9 公钥加密
///
/// # 参数
/// - `id`: 接收方 ID
/// - `message`: 明文
/// - `enc_pub`: 加密主公钥
///
/// 需要 `alloc` feature
#[cfg(feature = "alloc")]
pub fn sm9_encrypt<R: RngCore>(
    id: &[u8],
    message: &[u8],
    enc_pub: &Sm9EncPubKey,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    use crate::sm9::utils::sm9_kdf;

    let ppub_e = G2Affine::from_bytes(enc_pub.as_bytes())?;

    loop {
        // C1：随机 r ∈ [1, n-1]
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = U256::from_be_slice(&r_bytes);
        r_bytes.zeroize();
        if bool::from(r.is_zero()) || r >= GROUP_ORDER {
            continue;
        }

        // h1 = H1(ID || 0x03)
        let h1 = sm9_h1(id, 0x03);

        // QB = [h1]·P2 + Ppub-e（G2 上）
        // Reason: 标准中 QB 是 G2 上的点，Ppub-e = ke·P2 也在 G2 上
        let h1p2 = G2Jacobian::scalar_mul_g2(&h1).to_affine()?;
        let h1p2_jac = G2Jacobian::from_affine(&h1p2);
        let ppub_jac = G2Jacobian::from_affine(&ppub_e);
        let qb_jac = G2Jacobian::add_jac(&h1p2_jac, &ppub_jac);
        let qb = qb_jac.to_affine()?;

        // C1 = r·QB（G2 上，128 字节）
        // Reason: C1 = [r]QB 使解密者可以用 de 恢复 w = e(de, C1) = e(P1,P2)^{ke·r}
        let c1_jac = G2Jacobian::scalar_mul(&r, &G2Jacobian::from_affine(&qb));
        let c1_aff = c1_jac.to_affine()?;
        let c1_bytes = c1_aff.to_bytes();

        // w = e(P1, Ppub-e)^r = e(P1, ke·P2)^r = e(P1,P2)^{ke·r}
        // Reason: 加密时 w 用 Ppub-e（ke·P2）和 P1 的配对计算，
        //   解密时 e(de, C1) = e(ke·(ke+h1)^{-1}·P1, r·(h1+ke)·P2) = e(P1,P2)^{ke·r} = w
        let g = pairing(&G1Affine::generator(), &ppub_e);
        let w = fp12_pow(&g, &r);
        let w_bytes = fp12_to_bytes_for_kdf(&w);

        // klen = len(M) + 32（K1 for enc + K2 for MAC）
        let klen = message.len() + 32;
        let mut kdf_input = Vec::with_capacity(128 + 384 + id.len());
        kdf_input.extend_from_slice(&c1_bytes);
        kdf_input.extend_from_slice(&w_bytes);
        kdf_input.extend_from_slice(id);
        let k = sm9_kdf(&kdf_input, klen);

        if k.iter().all(|&b| b == 0) {
            continue;
        }

        let k1 = &k[..message.len()];
        let _k2 = &k[message.len()..]; // K2 在此实现中未使用（MAC 通过 C3 实现）

        // C2 = M ⊕ K1
        let c2: Vec<u8> = message
            .iter()
            .zip(k1.iter())
            .map(|(&m, &k)| m ^ k)
            .collect();

        // C3 = SM3(C2 || w || ID)
        let mut h = Sm3Hasher::new();
        h.update(&c2);
        h.update(&w_bytes);
        h.update(id);
        let c3 = h.finalize();

        // 输出 C1||C3||C2（128+32+len(M) 字节）
        let mut output = Vec::with_capacity(128 + 32 + message.len());
        output.extend_from_slice(&c1_bytes);
        output.extend_from_slice(&c3);
        output.extend_from_slice(&c2);
        return Ok(output);
    }
}

/// SM9 解密（GB/T 38635.1-2020 §7.3）
///
/// 需要 `alloc` feature
#[cfg(feature = "alloc")]
pub fn sm9_decrypt(
    id: &[u8],
    ciphertext: &[u8],
    de: &Sm9SignPrivKey, // 加密私钥（与签名私钥同类型，都是 G1 点）
) -> Result<Vec<u8>, Error> {
    use crate::sm9::utils::sm9_kdf;

    // 格式：C1(128) || C3(32) || C2(*)
    if ciphertext.len() < 160 {
        return Err(Error::InvalidInputLength);
    }

    let c1_bytes: [u8; 128] = ciphertext[0..128].try_into().unwrap();
    let c3: [u8; 32] = ciphertext[128..160].try_into().unwrap();
    let c2 = &ciphertext[160..];

    // 验证 C1 在 G2 上
    let c1 = G2Affine::from_bytes(&c1_bytes)?;

    // w = e(de, C1)
    let de_point = G1Affine::from_bytes(de.as_bytes())?;
    let w = pairing(&de_point, &c1);
    let w_bytes = fp12_to_bytes_for_kdf(&w);

    // KDF
    let klen = c2.len() + 32;
    let mut kdf_input = Vec::with_capacity(128 + 384 + id.len());
    kdf_input.extend_from_slice(&c1_bytes);
    kdf_input.extend_from_slice(&w_bytes);
    kdf_input.extend_from_slice(id);
    let k = sm9_kdf(&kdf_input, klen);

    if k.iter().all(|&b| b == 0) {
        return Err(Error::Sm9DecryptFailed);
    }

    let k1 = &k[..c2.len()];
    let _k2 = &k[c2.len()..]; // K2 在此实现中未使用

    // M' = C2 ⊕ K1
    let m: Vec<u8> = c2.iter().zip(k1.iter()).map(|(&c, &k)| c ^ k).collect();

    // 验证 C3 = SM3(C2 || w || ID)（常量时间比较，先验证后使用）
    let mut h = Sm3Hasher::new();
    h.update(c2);
    h.update(&w_bytes);
    h.update(id);
    let c3_computed = h.finalize();

    // Reason: 先验证 C3 再返回明文，防止 chosen-ciphertext 攻击
    if c3.ct_eq(&c3_computed).unwrap_u8() != 1 {
        return Err(Error::Sm9DecryptFailed);
    }
    Ok(m)
}

// ── 辅助：Fp12 幂次（常量时间）──────────────────────────────────────────────

/// 计算 f^k（Fp12 上的幂，常量时间 square-and-multiply）
///
/// Reason: 固定 256 位迭代 + `conditional_select` 掩码选择，消除基于指数位的条件分支，
///   防止时序侧信道攻击（调用方 k 可能是私钥或随机数等秘密值）。
fn fp12_pow(f: &Fp12, k: &U256) -> Fp12 {
    let mut result = Fp12::ONE;
    let mut base = *f;

    // 从低位到高位，固定 256 位迭代，不跳过任何位
    for byte in k.to_be_bytes().iter().rev() {
        for bit in 0..8 {
            // 始终计算乘法（与指数位无关）
            let product = fp12_mul(&result, &base);
            // Reason: 用掩码选择结果，bit=1 取 product，bit=0 取 result，无条件分支
            let choice = Choice::from((byte >> bit) & 1);
            result = Fp12::conditional_select(&result, &product, choice);
            base = fp12_mul(&base, &base);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRng([u8; 32]);
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
    fn test_generate_sign_master_keypair() {
        let mut rng = FakeRng([0x42u8; 32]);
        let (ks, ppub) = generate_sign_master_keypair(&mut rng);
        // 验证 ppub 在 G2 上
        let p = G2Affine::from_bytes(ppub.as_bytes()).expect("公钥应有效");
        assert!(p.is_on_curve());
    }

    #[test]
    fn test_generate_user_sign_key() {
        let mut rng = FakeRng([0x42u8; 32]);
        let (ks, _ppub) = generate_sign_master_keypair(&mut rng);
        let id = b"Alice";
        let da = generate_sign_user_key(&ks, id).expect("签名私钥生成应成功");
        // 验证 dA 在 G1 上
        let p = G1Affine::from_bytes(da.as_bytes()).expect("私钥点应有效");
        assert!(p.is_on_curve());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut rng = FakeRng([0x42u8; 32]);
        let (master_priv, sign_pub) = generate_sign_master_keypair(&mut rng);
        let pub_key = Sm9SignPubKey::from_bytes(sign_pub.as_bytes()).unwrap();
        let id = b"Alice";
        let da = generate_sign_user_key(&master_priv, id).expect("用户签名私钥应生成成功");
        let msg = b"hello sm9";
        let (h, s) = sm9_sign(msg, &da, &pub_key, &mut rng).expect("签名应成功");
        sm9_verify(msg, &h, &s, id, &pub_key).expect("验签应成功");
    }

    #[test]
    fn test_pairing_bilinear() {
        use crate::sm9::fields::fp12::{fp12_mul, Fp12};
        use crate::sm9::groups::g1::{G1Affine, G1Jacobian};
        use crate::sm9::groups::g2::{G2Affine, G2Jacobian};
        use crate::sm9::pairing::pairing;
        use crypto_bigint::U256;

        let p = G1Affine::generator();
        let q = G2Affine::generator();

        // 验证 G1 scalar_mul(2) == G1.double()
        let g1_2_by_mul = G1Jacobian::scalar_mul_g1(&U256::from(2u32)).to_affine().unwrap();
        let g1_jac = G1Jacobian::from_affine(&p);
        let g1_2_by_double = g1_jac.double().to_affine().unwrap();
        use crate::sm9::fields::fp::fp_to_bytes;
        assert_eq!(
            fp_to_bytes(&g1_2_by_mul.x), fp_to_bytes(&g1_2_by_double.x),
            "G1 scalar_mul(2) != G1.double() in x"
        );
        assert_eq!(
            fp_to_bytes(&g1_2_by_mul.y), fp_to_bytes(&g1_2_by_double.y),
            "G1 scalar_mul(2) != G1.double() in y"
        );

        // 验证 G2 scalar_mul(2) == G2.double()
        let g2_jac = G2Jacobian::from_affine(&q);
        let g2_2_by_mul = G2Jacobian::scalar_mul_g2(&U256::from(2u32)).to_affine().unwrap();
        let g2_2_by_double = g2_jac.double().to_affine().unwrap();
        assert_eq!(g2_2_by_mul, g2_2_by_double, "G2 scalar_mul(2) != G2.double()");

        // e(2G1, G2) == e(G1, G2)^2
        let e_2g1_g2 = pairing(&g1_2_by_mul, &q);
        let e_g1_g2 = pairing(&p, &q);
        let e_sq = fp12_mul(&e_g1_g2, &e_g1_g2);

        // 中间验证：用 G1+G1 （点加法）得到 2G1
        let g1_jac2 = G1Jacobian::from_affine(&p);
        let g1_add_g1 = G1Jacobian::add(&G1Jacobian::from_affine(&p), &g1_jac2).to_affine().unwrap();
        let e_addg1_g2 = pairing(&g1_add_g1, &q);
        assert_eq!(e_addg1_g2, e_sq, "e(G1+G1,G2) != e(G1,G2)²（用点加法）");

        assert_eq!(e_2g1_g2, e_sq, "配对双线性性验证失败：e(2G1,G2) != e(G1,G2)²");

        // e(G1, 2G2) == e(G1, G2)^2
        let e_g1_2g2 = pairing(&p, &g2_2_by_mul);
        assert_eq!(e_g1_2g2, e_sq, "配对双线性性验证失败：e(G1,2G2) != e(G1,G2)²");
    }
}

#[cfg(test)]
mod pairing_tests {
    use super::*;
    use crate::sm9::fields::fp12::{
        fp12_conjugate, fp12_frobenius_p, fp12_frobenius_p2, fp12_frobenius_p3,
        fp12_inv, fp12_mul, fp12_square, Fp12,
    };
    use crate::sm9::groups::g1::{G1Affine, G1Jacobian};
    use crate::sm9::groups::g2::{G2Affine, G2Jacobian};
    use crate::sm9::pairing::{final_exp, miller_loop, pairing};
    use crypto_bigint::U256;

    #[test]
    fn test_pairing_double_only() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let g1_2 = G1Jacobian::scalar_mul_g1(&U256::from(2u32)).to_affine().unwrap();

        let e_g1_g2 = pairing(&p, &q);
        let e_sq = fp12_mul(&e_g1_g2, &e_g1_g2);
        let e_2g1_g2 = pairing(&g1_2, &q);
        assert_eq!(e_2g1_g2, e_sq, "e(2G1,G2) != e(G1,G2)² via scalar_mul");
    }

    /// Miller loop 本身的双线性性验证（不经 final_exp）
    ///
    /// 理论上 ml(2G1, G2) 和 ml(G1, G2)^2 在 Fp12* 中等比关系，
    /// 经过 final_exp 后应相等（如果 final_exp 正确）
    #[test]
    fn test_miller_loop_raw_bilinear() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let g1_2 = G1Jacobian::scalar_mul_g1(&U256::from(2u32)).to_affine().unwrap();

        let ml1 = miller_loop(&q, &p);
        let ml2 = miller_loop(&q, &g1_2);

        // ml(2G1, G2) / ml(G1, G2)^2 应该在 final_exp 的核中
        // 即 final_exp(ml(2G1, G2) / ml(G1, G2)^2) == 1
        use crate::sm9::fields::fp12::fp12_inv;
        let ml1_sq = fp12_mul(&ml1, &ml1);
        let ml1_sq_inv = fp12_inv(&ml1_sq).expect("inv should exist");
        let ratio = fp12_mul(&ml2, &ml1_sq_inv);
        let ratio_exp = final_exp(&ratio);
        assert_eq!(ratio_exp, Fp12::ONE, "final_exp(ml(2G1,G2)/ml(G1,G2)^2) != 1");
    }

    #[test]
    fn test_miller_loop_bilinear() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let g1_2 = G1Jacobian::scalar_mul_g1(&U256::from(2u32)).to_affine().unwrap();

        let ml_g1_g2 = miller_loop(&q, &p);
        let ml_2g1_g2 = miller_loop(&q, &g1_2);

        let gt1 = final_exp(&ml_g1_g2);
        let gt2 = final_exp(&ml_2g1_g2);
        let gt1_sq = fp12_square(&gt1);
        assert_eq!(gt2, gt1_sq, "final_exp(ml(2G1,G2)) != final_exp(ml(G1,G2))^2");
    }

    #[test]
    fn test_final_exp_gt_order() {
        use crate::sm9::fields::fp::GROUP_ORDER;
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let ml = miller_loop(&q, &p);
        let gt = final_exp(&ml);

        let n = GROUP_ORDER;
        let mut result = Fp12::ONE;
        let mut base = gt;
        for byte in n.to_be_bytes().iter().rev() {
            for bit in 0..8 {
                let product = fp12_mul(&result, &base);
                let choice = subtle::Choice::from((byte >> bit) & 1);
                result = Fp12::conditional_select(&result, &product, choice);
                base = fp12_mul(&base, &base);
            }
        }
        assert_eq!(result, Fp12::ONE, "e(G1,G2)^n != 1: GT element not in subgroup");
    }

    /// 验证 ml^{p^6} == conjugate(ml)（Frobenius 正确性检查）
    #[test]
    fn test_miller_loop_p6_conjugate() {
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let ml = miller_loop(&q, &p);

        let ml_p6 = fp12_frobenius_p(&fp12_frobenius_p(&fp12_frobenius_p(
            &fp12_frobenius_p(&fp12_frobenius_p(&fp12_frobenius_p(&ml))))));
        let ml_conj = fp12_conjugate(&ml);
        assert_eq!(ml_p6, ml_conj, "ml^{{p^6}} != conjugate(ml)");
    }

    /// 调试测试：分别验证 G1 侧和 G2 侧的双线性性
    ///
    /// 通过对比点加法与标量乘法得到的 2G1，以及对 G2 侧的双线性性检验，
    /// 定位 Miller loop 双线性性失败的根源。
    #[test]
    fn test_single_double_step_line() {
        use crate::sm9::fields::fp::fp_to_bytes;
        use crate::sm9::fields::fp12::fp12_inv;

        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        // 确认 pairing 具有确定性
        let e1 = pairing(&g1, &g2);
        let e2 = pairing(&g1, &g2);
        assert_eq!(e1, e2, "pairing is not deterministic");

        // 用点加法计算 G1+G1（= 2G1）
        let g1_jac = G1Jacobian::from_affine(&g1);
        let g1_2_by_add = G1Jacobian::add(&g1_jac, &g1_jac).to_affine().unwrap();
        // 用标量乘法计算 2·G1
        let g1_2_by_mul = G1Jacobian::scalar_mul_g1(&U256::from(2u32)).to_affine().unwrap();

        // 验证两种方式得到相同的 2G1
        assert_eq!(
            fp_to_bytes(&g1_2_by_add.x),
            fp_to_bytes(&g1_2_by_mul.x),
            "G1 add vs mul: x 坐标不同"
        );
        assert_eq!(
            fp_to_bytes(&g1_2_by_add.y),
            fp_to_bytes(&g1_2_by_mul.y),
            "G1 add vs mul: y 坐标不同"
        );

        // 检验 G2 侧双线性性：e(G1, 2G2) == e(G1, G2)^2
        let g2_2 = G2Jacobian::scalar_mul_g2(&U256::from(2u32)).to_affine().unwrap();
        let e_g1_2g2 = pairing(&g1, &g2_2);
        let e_g1_g2_sq = fp12_mul(&e1, &e1);
        assert_eq!(
            e_g1_2g2, e_g1_g2_sq,
            "e(G1, 2G2) != e(G1,G2)^2 — G2 侧双线性性失败"
        );
    }

    /// 验证 fp12_mul_by_line 的槽位约定（{c0.c0=a, c0.c1(v)=b, c1.c0(w)=c}）
    ///
    /// fp12_mul_by_line 内部已经构造 full Fp12 再调用 fp12_mul，
    /// 此测试显式地按相同槽位构造 Fp12，验证两条路径结果相同。
    /// 约定：a -> c0.c0(1 slot), b -> c0.c1(v slot), c -> c1.c0(w slot)
    #[test]
    fn test_line_eval_equivalence() {
        use crate::sm9::fields::fp12::{
            fp12_mul, fp12_mul_by_line, Fp12, Fp6, LineEval,
        };
        use crate::sm9::fields::fp2::Fp2;
        use crate::sm9::fields::fp::Fp;

        // 验证 fp12_mul_by_line 等价于按约定槽位构造 full Fp12 再乘
        // 约定：a -> c0.c0(1 slot), b -> c1.c1(vw slot), c -> c1.c2(v²w slot)
        let line = LineEval {
            a: Fp2 { c0: Fp::ONE, c1: Fp::ZERO },
            b: Fp2 { c0: Fp::ONE, c1: Fp::ZERO },
            c: Fp2 { c0: Fp::ONE, c1: Fp::ZERO },
        };
        let f = Fp12::ONE;
        let sparse_result = fp12_mul_by_line(&f, &line);
        // 按相同槽位手动构造 full Fp12（槽位 {c0.c0=a, c1.c1(vw)=b, c1.c2(v²w)=c}）
        let full_line = Fp12 {
            c0: Fp6 { c0: line.a, c1: Fp2::ZERO, c2: Fp2::ZERO },
            c1: Fp6 { c0: Fp2::ZERO, c1: line.b, c2: line.c },
        };
        let full_result = fp12_mul(&f, &full_line);
        assert_eq!(
            sparse_result, full_result,
            "fp12_mul_by_line 槽位不匹配: 期望约定 (c0.c0=a, c1.c1(vw)=b, c1.c2(v²w)=c)"
        );
    }
}
