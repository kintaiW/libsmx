//! SM2 椭圆曲线点运算（GB/T 32918.1-2016 §4.2）
//!
//! 使用 Jacobian 射影坐标（X:Y:Z），仿射坐标满足 x = X/Z², y = Y/Z³。
//! 避免热路径中的 Fp 求逆运算，性能优于仿射坐标加法。

use crypto_bigint::U256;
use subtle::{Choice, ConditionallySelectable};

use crate::error::Error;
use crate::sm2::field::{
    fp_add, fp_from_bytes, fp_inv, fp_mul, fp_neg, fp_square, fp_sub, fp_to_bytes, Fp, CURVE_A,
    CURVE_B, FIELD_MODULUS, GX, GY,
};

// ── 仿射坐标点 ────────────────────────────────────────────────────────────────

/// SM2 曲线上的仿射坐标点（公开类型，用于序列化/反序列化）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    /// x 坐标
    pub x: Fp,
    /// y 坐标
    pub y: Fp,
}

// ── Jacobian 射影坐标点（内部运算专用）────────────────────────────────────────

/// SM2 曲线上的 Jacobian 射影坐标点（内部使用）
///
/// 仿射点 (x, y) 对应射影点 (X:Y:Z) 满足 x = X/Z², y = Y/Z³
#[derive(Clone, Copy, Debug)]
pub struct JacobianPoint {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

// ── Jacobian 常量时间选择 ──────────────────────────────────────────────────────

/// 为 JacobianPoint 实现常量时间条件选择
///
/// Reason: 标量乘中用掩码选择替代 if/else，消除基于标量位的条件分支。
impl ConditionallySelectable for JacobianPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        JacobianPoint {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl JacobianPoint {
    /// 无穷远点（群的单位元），用 Z=0 表示
    pub const INFINITY: Self = JacobianPoint {
        x: Fp::ONE,
        y: Fp::ONE,
        z: Fp::ZERO,
    };

    /// 从仿射坐标构造（Z=1）
    pub fn from_affine(p: &AffinePoint) -> Self {
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: Fp::ONE,
        }
    }

    /// 转换为仿射坐标（需要一次 Fp 求逆，仅在最终输出时使用）
    pub fn to_affine(&self) -> Result<AffinePoint, Error> {
        if self.is_infinity() {
            return Err(Error::PointAtInfinity);
        }
        let z_inv = fp_inv(&self.z).ok_or(Error::PointAtInfinity)?;
        let z_inv2 = fp_square(&z_inv);
        let z_inv3 = fp_mul(&z_inv2, &z_inv);
        Ok(AffinePoint {
            x: fp_mul(&self.x, &z_inv2),
            y: fp_mul(&self.y, &z_inv3),
        })
    }

    /// 判断是否为无穷远点（常量时间，公开接口）
    pub fn is_infinity(&self) -> bool {
        bool::from(self.ct_is_infinity())
    }

    /// 常量时间无穷远判断（内部辅助，返回 Choice）
    ///
    /// Reason: 返回 Choice 供 conditional_select 直接使用，避免 bool 转换后再转回 Choice
    fn ct_is_infinity(&self) -> Choice {
        // Reason: 用 ConstantTimeEq 比较所有 32 字节，执行时间与 Z 值无关，
        //   替代 Iterator::all 的短路求值（后者泄露 Z 坐标前缀信息）。
        use subtle::ConstantTimeEq;
        fp_to_bytes(&self.z).ct_eq(&[0u8; 32])
    }

    /// 点倍运算（Jacobian 坐标，a=-3 优化公式，完全常量时间）
    ///
    /// 公式来自 https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    /// SM2 曲线 a = p-3 ≡ -3 (mod p)，使用 a=-3 特化公式降低乘法次数。
    ///
    /// # 安全性
    /// 无条件执行完整运算，用 `conditional_select` 处理无穷远退化情况，
    /// 消除 `if is_infinity()` 分支对标量前导零位的泄露。
    pub fn double(&self) -> Self {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);

        let delta = fp_square(z1); // Z1²
        let gamma = fp_square(y1); // Y1²
        let beta = fp_mul(x1, &gamma); // X1·Y1²

        // alpha = 3·(X1-delta)·(X1+delta)  [a=-3 优化]
        let alpha = fp_mul(&fp_sub(x1, &delta), &fp_add(x1, &delta));
        let alpha = fp_add(&fp_add(&alpha, &alpha), &alpha); // 3·alpha

        // X3 = alpha² - 8·beta
        let x3 = fp_sub(&fp_square(&alpha), &double2(&double1(&beta)));

        // Z3 = (Y1+Z1)² - gamma - delta
        let z3 = fp_sub(&fp_sub(&fp_square(&fp_add(y1, z1)), &gamma), &delta);

        // Y3 = alpha·(4·beta - X3) - 8·gamma²
        let gamma2 = fp_square(&gamma);
        let y3 = fp_sub(
            &fp_mul(&alpha, &fp_sub(&double2(&beta), &x3)),
            &double2(&double1(&gamma2)),
        );

        let d = JacobianPoint { x: x3, y: y3, z: z3 };
        // Reason: 无穷远点的倍点仍为无穷远点；用掩码选择替代 if 分支，
        //   避免 scalar_mul 热路径中泄露哪些迭代位为前导零。
        JacobianPoint::conditional_select(&d, self, self.ct_is_infinity())
    }

    /// 点加运算（完全常量时间，无条件分支）
    ///
    /// 公式来自 https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
    ///
    /// # 安全性
    /// 采用"计算所有情况 + 掩码选择"策略，消除全部退化情况的条件分支：
    /// - P = ∞ → Q（无穷远加法单位元）
    /// - Q = ∞ → P
    /// - P = Q → double(P)（相同点，用 ct_eq 检测 H==0 且 R==0）
    /// - P = -Q → ∞（互反点，用 ct_eq 检测 H==0 且 R≠0）
    /// - 正常情况 → 标准 Jacobian 加法
    ///
    /// Reason: 原实现的 3 处 `if` 分支（is_infinity、H==0、R==0）
    ///   在 scalar_mul 热路径中泄露标量的汉明重量及位分布。
    pub fn add(p: &JacobianPoint, q: &JacobianPoint) -> JacobianPoint {
        use subtle::ConstantTimeEq;

        let z1sq = fp_square(&p.z);
        let z2sq = fp_square(&q.z);
        let u1 = fp_mul(&p.x, &z2sq); // X1·Z2²
        let u2 = fp_mul(&q.x, &z1sq); // X2·Z1²
        let s1 = fp_mul(&p.y, &fp_mul(&q.z, &z2sq)); // Y1·Z2³
        let s2 = fp_mul(&q.y, &fp_mul(&p.z, &z1sq)); // Y2·Z1³

        let h = fp_sub(&u2, &u1);
        let r = fp_sub(&s2, &s1);

        // 常量时间零判断（替代 Iterator::all 短路）
        let h_is_zero = fp_to_bytes(&h).ct_eq(&[0u8; 32]);
        let r_is_zero = fp_to_bytes(&r).ct_eq(&[0u8; 32]);

        // 无条件执行标准 Jacobian 加法（当 h==0 时结果为垃圾值，后续掩码覆盖）
        let h2 = fp_square(&h);
        let h3 = fp_mul(&h, &h2);
        let u1h2 = fp_mul(&u1, &h2);

        // X3 = R² - H³ - 2·U1·H²
        let x3 = fp_sub(&fp_sub(&fp_square(&r), &h3), &double1(&u1h2));
        // Y3 = R·(U1·H² - X3) - S1·H³
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&s1, &h3));
        // Z3 = H·Z1·Z2  （当 H==0 时 z3=0，即 INFINITY，与下面掩码一致）
        let z3 = fp_mul(&fp_mul(&h, &p.z), &q.z);
        let normal = JacobianPoint { x: x3, y: y3, z: z3 };

        // 预计算 P==Q 退化情况的结果（无条件执行，结果由掩码决定是否使用）
        let double_p = p.double();

        // 按优先级从低到高用 conditional_select 叠加（后面覆盖前面）：
        // 优先级 1（最低）：正常 Jacobian 加法
        let result = normal;
        // 优先级 2：P == -Q → INFINITY（h==0 且 r≠0）
        let result = JacobianPoint::conditional_select(
            &result, &JacobianPoint::INFINITY, h_is_zero & !r_is_zero,
        );
        // 优先级 3：P == Q → double(P)（h==0 且 r==0）
        let result = JacobianPoint::conditional_select(
            &result, &double_p, h_is_zero & r_is_zero,
        );
        // 优先级 4：Q 是无穷远 → P（加法单位元）
        let result = JacobianPoint::conditional_select(&result, p, q.ct_is_infinity());
        // 优先级 5（最高）：P 是无穷远 → Q
        JacobianPoint::conditional_select(&result, q, p.ct_is_infinity())
    }

    /// 标量乘 k·P（常量时间，固定 256 位迭代）
    ///
    /// Reason: 固定迭代次数 + `conditional_select` 掩码选择，消除基于标量位的条件分支，
    ///   防止时序侧信道攻击。执行路径与标量 k 的值完全无关。
    pub fn scalar_mul(k: &U256, p: &JacobianPoint) -> JacobianPoint {
        let mut result = JacobianPoint::INFINITY;

        // 固定 256 次迭代，不跳过前导零
        for byte in &k.to_be_bytes() {
            for b in (0..8).rev() {
                // 始终执行倍点（与标量位无关）
                result = result.double();

                // 始终计算加法（与标量位无关）
                let sum = JacobianPoint::add(&result, p);

                // Reason: 用掩码选择结果，无条件分支：bit=1 取 sum，bit=0 取 result
                let bit = Choice::from((byte >> b) & 1);
                result = JacobianPoint::conditional_select(&result, &sum, bit);
            }
        }
        result
    }

    /// 基点标量乘 k·G（密钥生成和签名专用）
    pub fn scalar_mul_g(k: &U256) -> JacobianPoint {
        let g = JacobianPoint::from_affine(&AffinePoint { x: GX, y: GY });
        Self::scalar_mul(k, &g)
    }
}

// ── 辅助倍增函数（用于 Jacobian 公式中的常数倍计算）────────────────────────

#[inline]
fn double1(a: &Fp) -> Fp {
    fp_add(a, a)
}

#[inline]
fn double2(a: &Fp) -> Fp {
    let t = double1(a);
    double1(&t)
}

// ── AffinePoint 公开接口 ──────────────────────────────────────────────────────

impl AffinePoint {
    /// SM2 基点 G
    pub fn generator() -> Self {
        AffinePoint { x: GX, y: GY }
    }

    /// 验证点是否在 SM2 曲线上：y² ≡ x³ + ax + b (mod p)
    pub fn is_on_curve(&self) -> bool {
        let x2 = fp_square(&self.x);
        let x3 = fp_mul(&x2, &self.x);
        let ax = fp_mul(&CURVE_A, &self.x);
        let rhs = fp_add(&fp_add(&x3, &ax), &CURVE_B);
        fp_square(&self.y) == rhs
    }

    /// 从未压缩格式 04||x||y（65 字节）解析点
    ///
    /// 符合 GB/T 32918.1-2016 §4.2.9
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, Error> {
        if bytes[0] != 0x04 {
            return Err(Error::InvalidPublicKey);
        }
        let x_bytes: [u8; 32] = bytes[1..33].try_into().unwrap();
        let y_bytes: [u8; 32] = bytes[33..65].try_into().unwrap();

        // 检查坐标在 [0, p-1] 范围内
        use crypto_bigint::subtle::ConstantTimeGreater;
        let x_val = U256::from_be_slice(&x_bytes);
        let y_val = U256::from_be_slice(&y_bytes);
        if bool::from(x_val.ct_gt(&FIELD_MODULUS))
            || x_val == FIELD_MODULUS
            || bool::from(y_val.ct_gt(&FIELD_MODULUS))
            || y_val == FIELD_MODULUS
        {
            return Err(Error::InvalidPublicKey);
        }

        let p = AffinePoint {
            x: fp_from_bytes(&x_bytes),
            y: fp_from_bytes(&y_bytes),
        };
        if !p.is_on_curve() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(p)
    }

    /// 序列化为未压缩格式 04||x||y（65 字节）
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&fp_to_bytes(&self.x));
        out[33..65].copy_from_slice(&fp_to_bytes(&self.y));
        out
    }

    /// 从压缩格式 02/03||x（33 字节）解压缩点
    ///
    /// 符合 GB/T 32918.1-2016 §4.2.10
    pub fn decompress(bytes: &[u8; 33]) -> Result<Self, Error> {
        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(Error::InvalidPublicKey);
        }
        let x_bytes: [u8; 32] = bytes[1..33].try_into().unwrap();

        use crypto_bigint::subtle::ConstantTimeGreater;
        let x_val = U256::from_be_slice(&x_bytes);
        if bool::from(x_val.ct_gt(&FIELD_MODULUS)) || x_val == FIELD_MODULUS {
            return Err(Error::InvalidPublicKey);
        }

        let x = fp_from_bytes(&x_bytes);

        // 计算 y² = x³ + ax + b
        let x2 = fp_square(&x);
        let x3 = fp_mul(&x2, &x);
        let ax = fp_mul(&CURVE_A, &x);
        let y2 = fp_add(&fp_add(&x3, &ax), &CURVE_B);

        let y = crate::sm2::field::fp_sqrt(&y2).ok_or(Error::InvalidPublicKey)?;

        // 按前缀奇偶性选择正确的 y
        // prefix 02 → 偶数（LSB=0），prefix 03 → 奇数（LSB=1）
        let y_lsb = fp_to_bytes(&y)[31] & 1;
        let want_odd = prefix & 1;
        let y_final = if y_lsb == want_odd { y } else { fp_neg(&y) };

        Ok(AffinePoint { x, y: y_final })
    }
}

// ── 双标量乘：u·G + v·Q（用于签名验证）─────────────────────────────────────

/// 计算 u·G + v·Q（顺序双标量乘，用于 SM2 验签第 3 步）
/// 双标量乘 u·G + v·Q（Shamir's trick 交错法，用于验签）
///
/// Reason: 验签时 u、v 均为公开值（非秘密），无需常量时间。
/// Shamir's trick 预计算 {P, Q, P+Q}，每位只需 1 次 double + 最多 1 次 add，
/// 比两次独立标量乘（各 256 次 double + 平均 128 add）快约 25%。
pub fn multi_scalar_mul(u: &U256, v: &U256, q: &AffinePoint) -> Result<AffinePoint, Error> {
    let g = AffinePoint::generator();
    let g_jac = JacobianPoint::from_affine(&g);
    let q_jac = JacobianPoint::from_affine(q);
    // 预计算 P+Q（G+Q）
    let gq_jac = JacobianPoint::add(&g_jac, &q_jac);

    let u_bytes = u.to_be_bytes();
    let v_bytes = v.to_be_bytes();

    let mut result = JacobianPoint::INFINITY;

    for i in 0..32 {
        let ub = u_bytes[i];
        let vb = v_bytes[i];
        for b in (0..8).rev() {
            result = result.double();
            let ui = (ub >> b) & 1;
            let vi = (vb >> b) & 1;
            // Reason: 根据两个标量位的组合，选择加哪个预计算点
            let addend = match (ui, vi) {
                (1, 0) => Some(&g_jac),
                (0, 1) => Some(&q_jac),
                (1, 1) => Some(&gq_jac),
                _ => None,
            };
            if let Some(p) = addend {
                result = JacobianPoint::add(&result, p);
            }
        }
    }
    result.to_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::field::{fp_to_bytes, GX, GY};

    #[test]
    fn test_generator_on_curve() {
        assert!(AffinePoint::generator().is_on_curve());
    }

    #[test]
    fn test_double_stays_on_curve() {
        let g = JacobianPoint::from_affine(&AffinePoint::generator());
        let g2 = g.double().to_affine().unwrap();
        assert!(g2.is_on_curve());
    }

    #[test]
    fn test_add_commutativity() {
        let g = JacobianPoint::from_affine(&AffinePoint::generator());
        let g2 = g.double();
        let p1 = JacobianPoint::add(&g2, &g).to_affine().unwrap();
        let p2 = JacobianPoint::add(&g, &g2).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&p1.x), fp_to_bytes(&p2.x));
        assert_eq!(fp_to_bytes(&p1.y), fp_to_bytes(&p2.y));
        assert!(p1.is_on_curve());
    }

    #[test]
    fn test_scalar_mul_one_is_g() {
        let g1 = JacobianPoint::scalar_mul_g(&U256::ONE).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&g1.x), fp_to_bytes(&GX));
        assert_eq!(fp_to_bytes(&g1.y), fp_to_bytes(&GY));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let g = AffinePoint::generator();
        let bytes = g.to_bytes();
        assert_eq!(bytes[0], 0x04);
        let g2 = AffinePoint::from_bytes(&bytes).unwrap();
        assert_eq!(fp_to_bytes(&g.x), fp_to_bytes(&g2.x));
        assert_eq!(fp_to_bytes(&g.y), fp_to_bytes(&g2.y));
    }

    #[test]
    fn test_keypair_on_curve() {
        // 测试私钥 → 公钥在曲线上
        let k_hex = "f927525e176ae5607c628bc508ec0465ef285b74415bf876130a8a5d004c789e";
        let k_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            for (i, chunk) in k_hex.as_bytes().chunks(2).enumerate() {
                b[i] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
            }
            b
        };
        let k = U256::from_be_slice(&k_bytes);
        let pub_aff = JacobianPoint::scalar_mul_g(&k).to_affine().unwrap();
        assert!(pub_aff.is_on_curve());
        // 验证 y² = x³ + ax + b
        let x2 = fp_square(&pub_aff.x);
        let x3 = fp_mul(&x2, &pub_aff.x);
        let ax = fp_mul(&CURVE_A, &pub_aff.x);
        let rhs = fp_add(&fp_add(&x3, &ax), &CURVE_B);
        assert_eq!(rhs, fp_square(&pub_aff.y));
    }

    /// 验证完备加法公式的退化情况（常量时间 add 的正确性）
    #[test]
    fn test_add_degenerate_cases() {
        let g = JacobianPoint::from_affine(&AffinePoint::generator());
        let inf = JacobianPoint::INFINITY;

        // ∞ + G = G
        let r = JacobianPoint::add(&inf, &g).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&r.x), fp_to_bytes(&GX), "∞ + G 的 x 坐标错误");
        assert_eq!(fp_to_bytes(&r.y), fp_to_bytes(&GY), "∞ + G 的 y 坐标错误");

        // G + ∞ = G
        let r = JacobianPoint::add(&g, &inf).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&r.x), fp_to_bytes(&GX), "G + ∞ 的 x 坐标错误");

        // G + G = 2G（通过 add 和 double 各算一次，结果应相同）
        let add_gg = JacobianPoint::add(&g, &g).to_affine().unwrap();
        let double_g = g.double().to_affine().unwrap();
        assert_eq!(
            fp_to_bytes(&add_gg.x),
            fp_to_bytes(&double_g.x),
            "add(G,G) != double(G) 的 x 坐标"
        );
        assert_eq!(
            fp_to_bytes(&add_gg.y),
            fp_to_bytes(&double_g.y),
            "add(G,G) != double(G) 的 y 坐标"
        );

        // G + (-G) = ∞（互反点，y 取负）
        let g_neg = JacobianPoint {
            x: g.x,
            y: fp_neg(&g.y),
            z: g.z,
        };
        assert!(JacobianPoint::add(&g, &g_neg).is_infinity(), "G + (-G) 应为无穷远点");
    }
}
