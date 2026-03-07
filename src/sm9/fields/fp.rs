//! SM9 BN256 基域 Fp 与标量域 Fn
//!
//! 曲线参数来自 GB/T 38635.1-2020 附录 A。
//! 使用 `crypto-bigint::ConstMontyForm` 实现常量时间 Montgomery 算术。

use crypto_bigint::{impl_modulus, modular::ConstMontyForm, U256};

// ── 模数定义 ──────────────────────────────────────────────────────────────────

// SM9 BN256 素数域模数 p
impl_modulus!(
    Sm9FieldModulus,
    U256,
    "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D"
);

// SM9 BN256 群阶 n
impl_modulus!(
    Sm9GroupOrder,
    U256,
    "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"
);

/// SM9 BN256 基域元素（常量时间 Montgomery 算术）
pub type Fp = ConstMontyForm<Sm9FieldModulus, { U256::LIMBS }>;

/// SM9 标量域元素（群阶 n 上的模运算）
pub type Fn = ConstMontyForm<Sm9GroupOrder, { U256::LIMBS }>;

// ── 曲线常量 ──────────────────────────────────────────────────────────────────

/// G1 基点 x 坐标
pub const G1X: Fp = Fp::new(&U256::from_be_hex(
    "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD",
));

/// G1 基点 y 坐标
pub const G1Y: Fp = Fp::new(&U256::from_be_hex(
    "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616",
));

/// 域模数 p（用于范围检查）
pub const FIELD_MODULUS: U256 =
    U256::from_be_hex("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D");

/// 群阶 n
pub const GROUP_ORDER: U256 =
    U256::from_be_hex("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25");

/// 群阶 n - 1
pub const GROUP_ORDER_MINUS_1: U256 =
    U256::from_be_hex("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF24");

// ── Fp 工具函数 ───────────────────────────────────────────────────────────────

/// 从大端字节构造 Fp（调用方保证值 < p）
#[inline]
pub fn fp_from_bytes(bytes: &[u8; 32]) -> Fp {
    Fp::new(&U256::from_be_slice(bytes))
}

/// 将 Fp 元素转为大端字节
#[inline]
pub fn fp_to_bytes(a: &Fp) -> [u8; 32] {
    a.retrieve().to_be_bytes()
}

/// 从大端字节构造 Fn（调用方保证值 < n）
#[inline]
pub fn fn_from_bytes(bytes: &[u8; 32]) -> Fn {
    Fn::new(&U256::from_be_slice(bytes))
}

/// 将 Fn 元素转为大端字节
#[inline]
pub fn fn_to_bytes(a: &Fn) -> [u8; 32] {
    a.retrieve().to_be_bytes()
}

/// Fp 加法（模 p）
#[inline]
pub fn fp_add(a: &Fp, b: &Fp) -> Fp {
    a.add(b)
}
/// Fp 减法（模 p）
#[inline]
pub fn fp_sub(a: &Fp, b: &Fp) -> Fp {
    a.sub(b)
}
/// Fp 乘法（模 p）
#[inline]
pub fn fp_mul(a: &Fp, b: &Fp) -> Fp {
    a.mul(b)
}
/// Fp 取反（模 p）
#[inline]
pub fn fp_neg(a: &Fp) -> Fp {
    a.neg()
}
/// Fp 平方（模 p）
#[inline]
pub fn fp_square(a: &Fp) -> Fp {
    a.square()
}

/// Fp 求逆（Bernstein-Yang，常量时间）
pub fn fp_inv(a: &Fp) -> Option<Fp> {
    let inv = a.inv();
    if bool::from(inv.is_some()) {
        Some(inv.unwrap())
    } else {
        None
    }
}

/// Fn 加法（群阶域加法，模 n）
#[inline]
pub fn fn_add(a: &Fn, b: &Fn) -> Fn {
    a.add(b)
}
/// Fn 减法（群阶域减法，模 n）
#[inline]
pub fn fn_sub(a: &Fn, b: &Fn) -> Fn {
    a.sub(b)
}
/// Fn 乘法（群阶域乘法，模 n）
#[inline]
pub fn fn_mul(a: &Fn, b: &Fn) -> Fn {
    a.mul(b)
}
/// Fn 取反（群阶域取反，模 n）
#[inline]
pub fn fn_neg(a: &Fn) -> Fn {
    a.neg()
}

/// Fn 求逆（Bernstein-Yang��常量时间）
pub fn fn_inv(a: &Fn) -> Option<Fn> {
    let inv = a.inv();
    if bool::from(inv.is_some()) {
        Some(inv.unwrap())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_add_sub() {
        let a = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let b = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]);
        assert_eq!(fp_to_bytes(&fp_sub(&fp_add(&a, &b), &b)), fp_to_bytes(&a));
    }

    #[test]
    fn test_fp_inv() {
        let two = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]);
        let inv = fp_inv(&two).expect("2^-1 应存在");
        assert_eq!(fp_mul(&two, &inv), Fp::ONE);
    }

    #[test]
    fn test_fn_inv() {
        let three = fn_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ]);
        let inv = fn_inv(&three).expect("3^-1 应存在");
        assert_eq!(fn_mul(&three, &inv), Fn::ONE);
    }
}
