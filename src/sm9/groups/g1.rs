//! SM9 BN256 G1 群操作（GB/T 38635.1-2020 §A.1）
//!
//! G1 是定义在 Fp 上的 BN256 曲线：y² = x³ + b，a=0
//! 使用 Jacobian 射影坐标进行高效运算。

use crypto_bigint::U256;
use subtle::{Choice, ConditionallySelectable};

use crate::error::Error;
use crate::sm9::fields::fp::{
    fp_add, fp_from_bytes, fp_inv, fp_mul, fp_square, fp_sub, fp_to_bytes, Fp, FIELD_MODULUS, G1X,
    G1Y,
};

// SM9 G1 曲线参数：y² = x³ + b，其中 a=0
const CURVE_B: Fp = Fp::new(&U256::from_be_hex(
    "0000000000000000000000000000000000000000000000000000000000000005",
));

// ── 仿射坐标点 ──────────────────────────────────────────────────────────────

/// G1 仿射坐标点
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine {
    /// x 坐标（Fp 元素）
    pub x: Fp,
    /// y 坐标（Fp 元素）
    pub y: Fp,
}

// ── Jacobian 射影坐标点 ──────────────────────────────────────────────────────

/// G1 Jacobian 射影坐标点（内部计算用）
///
/// 仿射 (x,y) 对应射影 (X:Y:Z)，满足 x=X/Z², y=Y/Z³
#[derive(Clone, Copy, Debug)]
pub struct G1Jacobian {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

impl ConditionallySelectable for G1Jacobian {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G1Jacobian {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl G1Jacobian {
    /// 无穷远点（Z=0）
    pub const INFINITY: Self = G1Jacobian {
        x: Fp::ONE,
        y: Fp::ONE,
        z: Fp::ZERO,
    };

    /// 从仿射坐标构造（Z=1）
    pub fn from_affine(p: &G1Affine) -> Self {
        G1Jacobian {
            x: p.x,
            y: p.y,
            z: Fp::ONE,
        }
    }

    /// 转换为仿射坐标（需要一次 Fp 求逆）
    pub fn to_affine(&self) -> Result<G1Affine, Error> {
        if self.is_infinity() {
            return Err(Error::PointAtInfinity);
        }
        let z_inv = fp_inv(&self.z).ok_or(Error::PointAtInfinity)?;
        let z_inv2 = fp_square(&z_inv);
        let z_inv3 = fp_mul(&z_inv2, &z_inv);
        Ok(G1Affine {
            x: fp_mul(&self.x, &z_inv2),
            y: fp_mul(&self.y, &z_inv3),
        })
    }

    /// 判断是否为无穷远点
    pub fn is_infinity(&self) -> bool {
        fp_to_bytes(&self.z).iter().all(|&b| b == 0)
    }

    /// 点倍运算（BN256 a=0 专用公式）
    ///
    /// 公式来自 https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    pub fn double(&self) -> Self {
        if self.is_infinity() {
            return *self;
        }

        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        // Reason: BN256 a=0，使用 dbl-2009-l 公式
        let a = fp_square(x1); // A = X1²
        let b = fp_square(y1); // B = Y1²
        let c = fp_square(&b); // C = B²

        // D = 2·((X1+B)²-A-C)
        // Reason: (X1+B)²-A-C = X1²+2·X1·B+B²-X1²-B² = 2·X1·Y1²
        let x1_b = fp_add(x1, &b);
        let tmp = fp_square(&x1_b); // (X1+B)²
        let tmp = fp_sub(&tmp, &a); // (X1+B)²-A
        let tmp = fp_sub(&tmp, &c); // (X1+B)²-A-C
        let d = fp_add(&tmp, &tmp); // D = 2·((X1+B)²-A-C) = 4·X1·Y1²

        let e = fp_add(&fp_add(&a, &a), &a); // 3·A = 3·X1²

        // X3 = E² - 2·D
        let x3 = fp_sub(&fp_square(&e), &fp_add(&d, &d));

        // Z3 = 2·Y1·Z1（dbl-2009-l，a=0 专用）
        // Reason: (Y1+Z1)²-B-Z1² 是 a=-3 的公式（dbl-2001-b），a=0 时应用 2·Y1·Z1
        let z3 = fp_add(&fp_mul(y1, z1), &fp_mul(y1, z1));

        // Y3 = E·(D-X3) - 8·C
        let eight_c = fp_add(
            &fp_add(&fp_add(&c, &c), &fp_add(&c, &c)),
            &fp_add(&fp_add(&c, &c), &fp_add(&c, &c)),
        );
        let y3 = fp_sub(&fp_mul(&e, &fp_sub(&d, &x3)), &eight_c);

        G1Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// 点加运算（完整公式，处理特殊情况）
    pub fn add(p: &G1Jacobian, q: &G1Jacobian) -> G1Jacobian {
        if p.is_infinity() {
            return *q;
        }
        if q.is_infinity() {
            return *p;
        }

        let z1sq = fp_square(&p.z);
        let z2sq = fp_square(&q.z);
        let u1 = fp_mul(&p.x, &z2sq);
        let u2 = fp_mul(&q.x, &z1sq);
        let s1 = fp_mul(&p.y, &fp_mul(&q.z, &z2sq));
        let s2 = fp_mul(&q.y, &fp_mul(&p.z, &z1sq));

        let h = fp_sub(&u2, &u1);
        let r = fp_sub(&s2, &s1);

        if fp_to_bytes(&h).iter().all(|&b| b == 0) {
            return if fp_to_bytes(&r).iter().all(|&b| b == 0) {
                p.double()
            } else {
                G1Jacobian::INFINITY
            };
        }

        let h2 = fp_square(&h);
        let h3 = fp_mul(&h, &h2);
        let u1h2 = fp_mul(&u1, &h2);

        let x3 = fp_sub(&fp_sub(&fp_square(&r), &h3), &fp_add(&u1h2, &u1h2));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&s1, &h3));
        let z3 = fp_mul(&fp_mul(&h, &p.z), &q.z);

        G1Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// 标量乘 k·P（常量时间，固定 256 位迭代）
    ///
    /// Reason: 固定迭代次数 + `conditional_select` 掩码选择，消除基于标量位的条件分支，
    ///   防止时序侧信道攻击。执行路径与标量 k 的值完全无关。
    pub fn scalar_mul(k: &U256, p: &G1Jacobian) -> G1Jacobian {
        let mut result = G1Jacobian::INFINITY;

        // 固定 256 次迭代，不跳过前导零
        for byte in &k.to_be_bytes() {
            for b in (0..8).rev() {
                result = result.double();
                let sum = G1Jacobian::add(&result, p);
                // Reason: 掩码选择，bit=1 取 sum，bit=0 取 result，无条件分支
                let bit = Choice::from((byte >> b) & 1);
                result = G1Jacobian::conditional_select(&result, &sum, bit);
            }
        }
        result
    }

    /// 基点 G1 标量乘
    pub fn scalar_mul_g1(k: &U256) -> G1Jacobian {
        let g = G1Jacobian::from_affine(&G1Affine { x: G1X, y: G1Y });
        Self::scalar_mul(k, &g)
    }
}

// ── G1Affine 公开接口 ────────────────────────────────────────────────────────

impl G1Affine {
    /// SM9 G1 基点
    pub fn generator() -> Self {
        G1Affine { x: G1X, y: G1Y }
    }

    /// 验证点是否在曲线上：y² = x³ + b
    pub fn is_on_curve(&self) -> bool {
        let x3 = fp_mul(&fp_square(&self.x), &self.x);
        let rhs = fp_add(&x3, &CURVE_B);
        fp_square(&self.y) == rhs
    }

    /// 从未压缩格式 04||x||y（65 字节）解析
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, Error> {
        if bytes[0] != 0x04 {
            return Err(Error::InvalidPublicKey);
        }
        let x_bytes: [u8; 32] = bytes[1..33].try_into().unwrap();
        let y_bytes: [u8; 32] = bytes[33..65].try_into().unwrap();

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

        let p = G1Affine {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_generator_on_curve() {
        assert!(G1Affine::generator().is_on_curve());
    }

    #[test]
    fn test_g1_double_on_curve() {
        let g = G1Jacobian::from_affine(&G1Affine::generator());
        let g2 = g.double().to_affine().unwrap();
        assert!(g2.is_on_curve());
    }

    #[test]
    fn test_g1_scalar_mul_one() {
        let g1 = G1Jacobian::scalar_mul_g1(&U256::ONE).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&g1.x), fp_to_bytes(&G1X));
        assert_eq!(fp_to_bytes(&g1.y), fp_to_bytes(&G1Y));
    }

    #[test]
    fn test_g1_add_commutativity() {
        let g = G1Jacobian::from_affine(&G1Affine::generator());
        let g2 = g.double();
        let p1 = G1Jacobian::add(&g, &g2).to_affine().unwrap();
        let p2 = G1Jacobian::add(&g2, &g).to_affine().unwrap();
        assert_eq!(fp_to_bytes(&p1.x), fp_to_bytes(&p2.x));
    }
}
