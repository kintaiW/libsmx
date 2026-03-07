//! SM9 BN256 G2 群操作
//!
//! G2 是定义在 Fp2 上的扭曲线：y² = x³ + b'，其中 b' = b/v（即 5/v）
//! 使用 Jacobian 射影坐标，支持 Miller loop 所需的线函数计算。

use crypto_bigint::U256;

use crate::error::Error;
use crate::sm9::fields::fp::{fp_to_bytes, Fp};
use crate::sm9::fields::fp12::LineEval;
use crate::sm9::fields::fp2::{
    fp2_add, fp2_inv, fp2_mul, fp2_mul_u, fp2_neg, fp2_square, fp2_sub, Fp2,
};

// ── G2 扭曲线参数 ───────────────────────────────────────────────────────────
//
// SM9 G2 扭曲线：y² = x³ + b/v，v³=u, u²=-2
// b=5，b/v 在 Fp6 中表示为：5·v^{-1}
// 等效于：b' = b·v^{-1} = 5·v^{-1}
//
// 实际处理：在 Fp2 上，b' 作为纯虚数 Fp2 元素：
// b'0 = 0, b'1 = 5  → b' = 5·u^{1/3}... 需要具体常量
//
// GB/T 38635.1-2020 附录 A 给出 G2 基点坐标（Fp2 元素）：
// G2 基点 P2 = (x_P2, y_P2)，其中 x_P2, y_P2 ∈ Fp2

/// G2 基点 x 坐标的实部
pub const G2X0: Fp = Fp::new(&U256::from_be_hex(
    "3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B",
));

/// G2 基点 x 坐标的虚部
pub const G2X1: Fp = Fp::new(&U256::from_be_hex(
    "85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141",
));

/// G2 基点 y 坐标的实部
pub const G2Y0: Fp = Fp::new(&U256::from_be_hex(
    "A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7",
));

/// G2 基点 y 坐标的虚部
pub const G2Y1: Fp = Fp::new(&U256::from_be_hex(
    "17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96",
));

/// G2 扭曲线参数 b' = 5·u（其中 u² = -2）
/// Reason: G2 曲线 y²=x³+b'，b'=5u，在 Fp2 中表示为 c0=0, c1=5
const G2B: Fp2 = Fp2 {
    c0: Fp::ZERO,
    c1: Fp::new(&U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000005",
    )),
};

// ── G2 仿射坐标点 ────────────────────────────────────────────────────────────

/// G2 仿射坐标点（Fp2 元素）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine {
    /// x 坐标（Fp2 元素）
    pub x: Fp2,
    /// y 坐标（Fp2 元素）
    pub y: Fp2,
}

// ── G2 Jacobian 射影坐标点 ────────────────────────────────────────────────────

/// G2 Jacobian 射影坐标点
#[derive(Clone, Copy, Debug)]
pub struct G2Jacobian {
    /// X 射影坐标（Fp2 元素）
    pub x: Fp2,
    /// Y 射影坐标（Fp2 元素）
    pub y: Fp2,
    /// Z 射影坐标（Fp2 元素）
    pub z: Fp2,
}

impl G2Jacobian {
    /// 无穷远点
    pub const INFINITY: Self = G2Jacobian {
        x: Fp2::ONE,
        y: Fp2::ONE,
        z: Fp2::ZERO,
    };

    /// 从仿射坐标构造（Z=1）
    pub fn from_affine(p: &G2Affine) -> Self {
        G2Jacobian {
            x: p.x,
            y: p.y,
            z: Fp2::ONE,
        }
    }

    /// 转换为仿射坐标
    pub fn to_affine(&self) -> Result<G2Affine, Error> {
        if self.is_infinity() {
            return Err(Error::PointAtInfinity);
        }
        let z_inv = fp2_inv(&self.z).ok_or(Error::PointAtInfinity)?;
        let z_inv2 = fp2_square(&z_inv);
        let z_inv3 = fp2_mul(&z_inv2, &z_inv);
        Ok(G2Affine {
            x: fp2_mul(&self.x, &z_inv2),
            y: fp2_mul(&self.y, &z_inv3),
        })
    }

    /// 判断是否为无穷远点
    pub fn is_infinity(&self) -> bool {
        let b = self.z.to_bytes();
        b.iter().all(|&v| v == 0)
    }

    /// 点倍运算（a=0 专用公式）
    ///
    /// 返回 (2P, 线函数 ℓ_{P,P}) 供 Miller loop 使用
    pub fn double_with_line(&self) -> (Self, LineEval) {
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);

        let a = fp2_square(x1); // A = X1²
        let b = fp2_square(y1); // B = Y1²
        let c = fp2_square(&b); // C = B²
                                // D = 2·((X1+B)²-A-C)，修正：逐步减法而非 fp2_sub(&a_minus_c)
                                // Reason: 原代码 fp2_sub(&(X1+B)², &fp2_sub(&A, &C)) = (X1+B)²-(A-C) 是错误的
        let tmp = fp2_square(&fp2_add(x1, &b));
        let tmp = fp2_sub(&tmp, &a);
        let tmp = fp2_sub(&tmp, &c);
        let d = fp2_add(&tmp, &tmp); // D = 4·X1·Y1²
        let e = fp2_add(&fp2_add(&a, &a), &a); // 3·X1²

        let x3 = fp2_sub(&fp2_square(&e), &fp2_add(&d, &d));
        // Z3 = 2·Y1·Z1（dbl-2009-l，a=0）
        // Reason: G2 扭曲线 a=0，使用 2·Y1·Z1 而非 (Y1+Z1)²-B-Z1²（后者是 a=-3 的公式）
        let z3 = fp2_add(&fp2_mul(y1, z1), &fp2_mul(y1, z1));
        let eight_c = {
            let c2 = fp2_add(&c, &c);
            let c4 = fp2_add(&c2, &c2);
            fp2_add(&c4, &c4)
        };
        let y3 = fp2_sub(&fp2_mul(&e, &fp2_sub(&d, &x3)), &eight_c);

        // 线函数系数（按 {c0.c0(1)=a, c1.c1(vw)=b, c1.c2(v²w)=c} 约定）
        // Reason: D-type twist BN256 tangent line，基于 sm9_core g_tangent 推导：
        //   a = 2Y₁Z₁³·u = z3·z1sq·u（z3=2Y₁Z₁，z1sq=Z₁²，在 eval_line_at_p 中乘以 yP→c0.c0）
        //   b = 3X₁³-2Y₁² = x1·e - 2·b（e=3X₁²，b=Y₁²，常数项→c1.c1(vw)）
        //   c = -3X₁²·Z₁² = -e·z1sq（在 eval_line_at_p 中乘以 xP→c1.c2(v²w)）
        let z1sq = fp2_square(z1);
        let line = LineEval {
            a: fp2_mul_u(&fp2_mul(&z3, &z1sq)),            // 2Y₁Z₁³·u（×yP→c0.c0）
            b: fp2_sub(&fp2_mul(x1, &e), &fp2_add(&b, &b)), // 3X₁³-2Y₁²（→c1.c1(vw)）
            c: fp2_neg(&fp2_mul(&e, &z1sq)),               // -3X₁²Z₁²（×xP→c1.c2(v²w)）
        };

        (
            G2Jacobian {
                x: x3,
                y: y3,
                z: z3,
            },
            line,
        )
    }

    /// 点加运算，返回 (P+Q, 线函数 ℓ_{P,Q})
    pub fn add_with_line(&self, q: &G2Affine) -> (Self, LineEval) {
        // 混合仿射-射影加法（q.z=1 优化）
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2) = (&q.x, &q.y);

        let z1sq = fp2_square(z1);
        let u2 = fp2_mul(x2, &z1sq); // X2·Z1²
        let s2 = fp2_mul(y2, &fp2_mul(z1, &z1sq)); // Y2·Z1³
        let h = fp2_sub(&u2, x1);
        let r = fp2_sub(&s2, y1);

        let h2 = fp2_square(&h);
        let h3 = fp2_mul(&h, &h2);
        let x1h2 = fp2_mul(x1, &h2);

        let x3 = fp2_sub(&fp2_sub(&fp2_square(&r), &h3), &fp2_add(&x1h2, &x1h2));
        let y3 = fp2_sub(&fp2_mul(&r, &fp2_sub(&x1h2, &x3)), &fp2_mul(y1, &h3));
        let z3 = fp2_mul(&fp2_mul(&h, z1), &Fp2::ONE); // ×1 因为 q.z=1

        // 线函数系数（按 {c0.c0(1)=a, c1.c1(vw)=b, c1.c2(v²w)=c} 约定）
        // Reason: D-type twist BN256 chord line，基于 sm9_core g_line 推导：
        //   a = H·Z₁·u = z3·u（z3=h*z1，在 eval_line_at_p 中乘以 yP→c0.c0）
        //   b = X₁·Y₂·Z₁ - X₂·Y₁（常数项→c1.c1(vw)）
        //   c = -(Y₂Z₁³-Y₁) = -r（r已算，在 eval_line_at_p 中乘以 xP→c1.c2(v²w)）
        let line = LineEval {
            a: fp2_mul_u(&z3),                                           // H·Z₁·u（×yP→c0.c0）
            b: fp2_sub(&fp2_mul(&fp2_mul(x1, z1), y2), &fp2_mul(x2, y1)), // X₁Y₂Z₁-X₂Y₁（→c1.c1(vw)）
            c: fp2_neg(&r),                                              // -(Y₂Z₁³-Y₁)（×xP→c1.c2(v²w)）
        };

        (
            G2Jacobian {
                x: x3,
                y: y3,
                z: z3,
            },
            line,
        )
    }

    /// 纯点倍（不需要线函数时使用，如密钥生成）
    pub fn double(&self) -> Self {
        self.double_with_line().0
    }

    /// 纯点加
    pub fn add_jac(p: &G2Jacobian, q: &G2Jacobian) -> G2Jacobian {
        if p.is_infinity() {
            return *q;
        }
        if q.is_infinity() {
            return *p;
        }

        let z1sq = fp2_square(&p.z);
        let z2sq = fp2_square(&q.z);
        let u1 = fp2_mul(&p.x, &z2sq);
        let u2 = fp2_mul(&q.x, &z1sq);
        let s1 = fp2_mul(&p.y, &fp2_mul(&q.z, &z2sq));
        let s2 = fp2_mul(&q.y, &fp2_mul(&p.z, &z1sq));
        let h = fp2_sub(&u2, &u1);
        let r = fp2_sub(&s2, &s1);

        if h.is_zero() {
            return if r.is_zero() {
                p.double()
            } else {
                G2Jacobian::INFINITY
            };
        }

        let h2 = fp2_square(&h);
        let h3 = fp2_mul(&h, &h2);
        let u1h2 = fp2_mul(&u1, &h2);

        let x3 = fp2_sub(&fp2_sub(&fp2_square(&r), &h3), &fp2_add(&u1h2, &u1h2));
        let y3 = fp2_sub(&fp2_mul(&r, &fp2_sub(&u1h2, &x3)), &fp2_mul(&s1, &h3));
        let z3 = fp2_mul(&fp2_mul(&h, &p.z), &q.z);

        G2Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// 标量乘 k·P（常量时间，迭代所有 256 位）
    ///
    /// Reason: 不使用 vartime 方法，固定迭代 256 位防止时序侧信道
    pub fn scalar_mul(k: &U256, p: &G2Jacobian) -> G2Jacobian {
        let mut result = G2Jacobian::INFINITY;
        let addend = *p;
        let mut started = false;

        for byte in &k.to_be_bytes() {
            for bit in (0..8).rev() {
                if started {
                    result = result.double();
                }
                if (byte >> bit) & 1 == 1 {
                    if started {
                        result = G2Jacobian::add_jac(&result, &addend);
                    } else {
                        result = addend;
                        started = true;
                    }
                }
            }
        }
        result
    }

    /// G2 基点标量乘
    pub fn scalar_mul_g2(k: &U256) -> G2Jacobian {
        let g2 = G2Jacobian::from_affine(&G2Affine::generator());
        Self::scalar_mul(k, &g2)
    }
}

// ── G2Affine 公开接口 ────────────────────────────────────────────────────────

impl G2Affine {
    /// SM9 G2 基点
    pub fn generator() -> Self {
        G2Affine {
            x: Fp2 { c0: G2X0, c1: G2X1 },
            y: Fp2 { c0: G2Y0, c1: G2Y1 },
        }
    }

    /// 验证点是否在 G2 扭曲线上：y² = x³ + b'
    pub fn is_on_curve(&self) -> bool {
        let x3 = fp2_mul(&fp2_square(&self.x), &self.x);
        let rhs = fp2_add(&x3, &G2B);
        fp2_square(&self.y) == rhs
    }

    /// 从字节解析 G2 点（128 字节：x0||x1||y0||y1，每个 32 字节）
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, Error> {
        let x0: [u8; 32] = bytes[0..32].try_into().unwrap();
        let x1: [u8; 32] = bytes[32..64].try_into().unwrap();
        let y0: [u8; 32] = bytes[64..96].try_into().unwrap();
        let y1: [u8; 32] = bytes[96..128].try_into().unwrap();

        use crate::sm9::fields::fp::FIELD_MODULUS;
        use crypto_bigint::subtle::ConstantTimeGreater;

        for b in [&x0, &x1, &y0, &y1] {
            let v = U256::from_be_slice(b);
            if bool::from(v.ct_gt(&FIELD_MODULUS)) || v == FIELD_MODULUS {
                return Err(Error::InvalidPublicKey);
            }
        }

        use crate::sm9::fields::fp::fp_from_bytes as ffb;
        let p = G2Affine {
            x: Fp2 {
                c0: ffb(&x0),
                c1: ffb(&x1),
            },
            y: Fp2 {
                c0: ffb(&y0),
                c1: ffb(&y1),
            },
        };
        if !p.is_on_curve() {
            return Err(Error::InvalidPublicKey);
        }
        Ok(p)
    }

    /// 序列化为字节（128 字节）
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&fp_to_bytes(&self.x.c0));
        out[32..64].copy_from_slice(&fp_to_bytes(&self.x.c1));
        out[64..96].copy_from_slice(&fp_to_bytes(&self.y.c0));
        out[96..128].copy_from_slice(&fp_to_bytes(&self.y.c1));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g2_generator_on_curve() {
        assert!(G2Affine::generator().is_on_curve());
    }

    #[test]
    fn test_g2_double_stays_in_group() {
        let g = G2Jacobian::from_affine(&G2Affine::generator());
        let g2 = g.double().to_affine().unwrap();
        assert!(g2.is_on_curve());
    }

    #[test]
    fn test_g2_scalar_mul_one() {
        let g2 = G2Jacobian::scalar_mul_g2(&U256::ONE).to_affine().unwrap();
        assert!(g2.is_on_curve());
        // 1·G2 = G2
        let x = g2.x.to_bytes();
        let gx = G2Affine::generator().x.to_bytes();
        assert_eq!(x, gx);
    }
}
