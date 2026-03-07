//! SM9 BN256 二次扩域 Fp2
//!
//! `Fp2 = Fp[u] / (u² + 2)`
//! 即 u² = -2
//!
//! 元素表示为 a = a0 + a1·u，其中 a0, a1 ∈ Fp

use crate::sm9::fields::fp::{
    fp_add, fp_from_bytes, fp_inv, fp_mul, fp_neg, fp_square, fp_sub, fp_to_bytes, Fp,
};
use subtle::{Choice, ConditionallySelectable};

impl ConditionallySelectable for Fp2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp2 {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

/// Fp2 元素：a = a0 + a1·u，u² = -2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp2 {
    /// 实部
    pub c0: Fp,
    /// 虚部（u 的系数）
    pub c1: Fp,
}

impl Fp2 {
    /// 零元
    pub const ZERO: Self = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };

    /// 单位元
    pub const ONE: Self = Fp2 {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    /// 从字节构造（64 字节：c0 前 32 字节，c1 后 32 字节）
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let c0 = fp_from_bytes(bytes[0..32].try_into().unwrap());
        let c1 = fp_from_bytes(bytes[32..64].try_into().unwrap());
        Fp2 { c0, c1 }
    }

    /// 序列化为字节（64 字节）
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&fp_to_bytes(&self.c0));
        out[32..64].copy_from_slice(&fp_to_bytes(&self.c1));
        out
    }

    /// 判断是否为零
    pub fn is_zero(&self) -> bool {
        fp_to_bytes(&self.c0).iter().all(|&b| b == 0)
            && fp_to_bytes(&self.c1).iter().all(|&b| b == 0)
    }
}

// ── Fp2 算术 ────────────────────────────────────────────────────────────────

/// Fp2 加法：(a0+a1·u) + (b0+b1·u) = (a0+b0) + (a1+b1)·u
#[inline]
pub fn fp2_add(a: &Fp2, b: &Fp2) -> Fp2 {
    Fp2 {
        c0: fp_add(&a.c0, &b.c0),
        c1: fp_add(&a.c1, &b.c1),
    }
}

/// Fp2 减法
#[inline]
pub fn fp2_sub(a: &Fp2, b: &Fp2) -> Fp2 {
    Fp2 {
        c0: fp_sub(&a.c0, &b.c0),
        c1: fp_sub(&a.c1, &b.c1),
    }
}

/// Fp2 取反
#[inline]
pub fn fp2_neg(a: &Fp2) -> Fp2 {
    Fp2 {
        c0: fp_neg(&a.c0),
        c1: fp_neg(&a.c1),
    }
}

/// Fp2 乘法（Karatsuba + u²=-2 规约）
///
/// (a0+a1·u)(b0+b1·u) = (a0b0 - 2·a1b1) + (a0b1 + a1b0)·u
/// Reason: u²=-2 导致实部有 -2 因子，用减法实现
pub fn fp2_mul(a: &Fp2, b: &Fp2) -> Fp2 {
    let a0b0 = fp_mul(&a.c0, &b.c0);
    let a1b1 = fp_mul(&a.c1, &b.c1);
    // c0 = a0b0 - 2·a1b1
    let two_a1b1 = fp_add(&a1b1, &a1b1);
    let c0 = fp_sub(&a0b0, &two_a1b1);
    // c1 = a0b1 + a1b0
    let a0b1 = fp_mul(&a.c0, &b.c1);
    let a1b0 = fp_mul(&a.c1, &b.c0);
    let c1 = fp_add(&a0b1, &a1b0);
    Fp2 { c0, c1 }
}

/// Fp2 平方（优化：3M → 2M + 3A）
///
/// (a0+a1·u)² = (a0²-2a1²) + 2·a0·a1·u
pub fn fp2_square(a: &Fp2) -> Fp2 {
    let a0sq = fp_square(&a.c0);
    let a1sq = fp_square(&a.c1);
    // c0 = a0² - 2·a1²
    let c0 = fp_sub(&a0sq, &fp_add(&a1sq, &a1sq));
    // c1 = 2·a0·a1
    let a0a1 = fp_mul(&a.c0, &a.c1);
    let c1 = fp_add(&a0a1, &a0a1);
    Fp2 { c0, c1 }
}

/// Fp2 求逆：1/(a0+a1·u) = (a0-a1·u)/(a0²+2·a1²)
pub fn fp2_inv(a: &Fp2) -> Option<Fp2> {
    let a0sq = fp_square(&a.c0);
    let a1sq = fp_square(&a.c1);
    // norm = a0² + 2·a1²
    let norm = fp_add(&a0sq, &fp_add(&a1sq, &a1sq));
    let norm_inv = fp_inv(&norm)?;
    Some(Fp2 {
        c0: fp_mul(&a.c0, &norm_inv),
        c1: fp_neg(&fp_mul(&a.c1, &norm_inv)),
    })
}

/// Fp2 乘以 Fp 标量
#[inline]
pub fn fp2_mul_fp(a: &Fp2, b: &Fp) -> Fp2 {
    Fp2 {
        c0: fp_mul(&a.c0, b),
        c1: fp_mul(&a.c1, b),
    }
}

/// Fp2 乘以虚数单位 u：(a0+a1·u)·u = a0·u + a1·u² = -2·a1 + a0·u
#[inline]
pub fn fp2_mul_u(a: &Fp2) -> Fp2 {
    // Reason: u²=-2，所以 (a0+a1·u)·u = a0·u - 2·a1
    let two_a1 = fp_add(&a.c1, &a.c1);
    Fp2 {
        c0: fp_neg(&two_a1),
        c1: a.c0,
    }
}

/// Fp2 Frobenius（p 次幂）：conjugate
///
/// (a0+a1·u)^p = a0 - a1·u（因为 u^p = -u in Fp2 when p ≡ 3 mod 4 mod the ext poly）
/// Reason: 对于 SM9 的 BN256，Frobenius 在 Fp2 上等同于共轭
#[inline]
pub fn fp2_frobenius(a: &Fp2) -> Fp2 {
    Fp2 {
        c0: a.c0,
        c1: fp_neg(&a.c1),
    }
}

/// Fp2 共轭（与 Frobenius 相同）
#[inline]
pub fn fp2_conjugate(a: &Fp2) -> Fp2 {
    fp2_frobenius(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp2_one() -> Fp2 {
        Fp2::ONE
    }
    fn fp2_two() -> Fp2 {
        let two = fp_add(&Fp::ONE, &Fp::ONE);
        Fp2 {
            c0: two,
            c1: Fp::ZERO,
        }
    }

    #[test]
    fn test_fp2_add_sub() {
        let a = fp2_two();
        let b = fp2_one();
        let c = fp2_add(&a, &b);
        let d = fp2_sub(&c, &b);
        assert_eq!(d, a);
    }

    #[test]
    fn test_fp2_mul_one() {
        let a = fp2_two();
        let r = fp2_mul(&a, &Fp2::ONE);
        assert_eq!(r, a);
    }

    #[test]
    fn test_fp2_square_vs_mul() {
        let a = fp2_two();
        let s = fp2_square(&a);
        let m = fp2_mul(&a, &a);
        assert_eq!(s, m);
    }

    #[test]
    fn test_fp2_inv() {
        let a = fp2_two();
        let inv = fp2_inv(&a).expect("2^-1 应存在");
        assert_eq!(fp2_mul(&a, &inv), Fp2::ONE);
    }

    #[test]
    fn test_fp2_u_squared() {
        // u² = -2，即 Fp2::from_u().square() = -2
        let u = Fp2 {
            c0: Fp::ZERO,
            c1: Fp::ONE,
        };
        let u2 = fp2_square(&u);
        // u² = 0 - 2·1 + 0·u = -2 + 0·u
        let neg_two = fp_neg(&fp_add(&Fp::ONE, &Fp::ONE));
        assert_eq!(u2.c0, neg_two);
        assert_eq!(fp_to_bytes(&u2.c1), [0u8; 32]);
    }
}
