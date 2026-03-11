//! SM2 sm2p256v1 素域 Fp 与标量域 Fn
//!
//! 曲线参数来自 GB/T 32918.1-2016 附录 A。
//! 所有算术通过 `crypto-bigint` 的 `ConstMontyForm` 实现，常量时间。

use crypto_bigint::{impl_modulus, modular::ConstMontyForm, U256};

// ── 模数定义 ──────────────────────────────────────────────────────────────────

// SM2 素数域模数 p
// p = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
impl_modulus!(
    Sm2FieldModulus,
    U256,
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
);

// SM2 群阶 n
// n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
impl_modulus!(
    Sm2GroupOrder,
    U256,
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
);

/// SM2 素域元素（基于 Montgomery 形式的常量时间运算）
pub type Fp = ConstMontyForm<Sm2FieldModulus, { U256::LIMBS }>;

/// SM2 标量域元素（群阶 n 上的模运算）
pub type Fn = ConstMontyForm<Sm2GroupOrder, { U256::LIMBS }>;

// ── 曲线参数常量（GB/T 32918.1-2016 附录 A）─────────────────────────────────

/// 曲线系数 a = p - 3
pub const CURVE_A: Fp = Fp::new(&U256::from_be_hex(
    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
));

/// 曲线系数 b
pub const CURVE_B: Fp = Fp::new(&U256::from_be_hex(
    "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
));

/// 基点 G 的 x 坐标
pub const GX: Fp = Fp::new(&U256::from_be_hex(
    "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
));

/// 基点 G 的 y 坐标
pub const GY: Fp = Fp::new(&U256::from_be_hex(
    "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
));

/// 域模数 p（用于坐标范围检查）
pub const FIELD_MODULUS: U256 =
    U256::from_be_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");

/// 群阶 n（用于标量范围检查）
pub const GROUP_ORDER: U256 =
    U256::from_be_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");

/// 群阶 n - 1（私钥合法性检查：d ∈ [1, n-2] → d < n-1）
pub const GROUP_ORDER_MINUS_1: U256 =
    U256::from_be_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122");

// ── Fp 工具函数 ───────────────────────────────────────────────────────────────

/// 从大端字节构造 Fp（调用方保证 bytes 表示的值 < p）
#[inline]
pub fn fp_from_bytes(bytes: &[u8; 32]) -> Fp {
    Fp::new(&U256::from_be_slice(bytes))
}

/// 将 Fp 元素转为大端字节
#[inline]
pub fn fp_to_bytes(a: &Fp) -> [u8; 32] {
    a.retrieve().to_be_bytes()
}

/// 从大端字节构造 Fn（标量，调用方保证值 < n）
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

/// Fp 乘法（Montgomery 乘，常量时间）
#[inline]
pub fn fp_mul(a: &Fp, b: &Fp) -> Fp {
    a.mul(b)
}

/// Fp 取负（模 p）
#[inline]
pub fn fp_neg(a: &Fp) -> Fp {
    a.neg()
}

/// Fp 平方（常量时间）
#[inline]
pub fn fp_square(a: &Fp) -> Fp {
    a.square()
}

/// Fp 求逆（Bernstein-Yang 算法，常量时间）
/// 返回 None 当且仅当 a == 0
pub fn fp_inv(a: &Fp) -> Option<Fp> {
    let inv = a.inv();
    // CtOption 转换为 Option
    if bool::from(inv.is_some()) {
        // Reason: ConstantTimeEq 保证此 unwrap 不可能 panic（is_some 为真）
        Some(inv.unwrap())
    } else {
        None
    }
}

/// Fp 平方根（用于点解压缩）
///
/// SM2 素数 p ≡ 3 (mod 4)，故 sqrt(a) = a^((p+1)/4) mod p。
/// 若结果的平方 ≠ a，则 a 不是二次剩余，返回 None。
pub fn fp_sqrt(a: &Fp) -> Option<Fp> {
    // (p+1)/4 = 3FFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFFFFFC000000040000000000000000
    // p = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 00000000 FFFFFFFFFFFFFFFF
    // p+1 = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 00000001 0000000000000000
    // /4 (右移2位) = 3FFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFFFFFC0000000 40000000 00000000
    let exp = U256::from_be_hex("3FFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC00000004000000000000000");
    let candidate = a.pow(&exp);
    // 验证 candidate^2 == a（常量时间比较，ConstMontyForm 的 PartialEq 是常量时间）
    if candidate.square() == *a {
        Some(candidate)
    } else {
        None
    }
}

/// Fn 加法（模 n）
#[inline]
pub fn fn_add(a: &Fn, b: &Fn) -> Fn {
    a.add(b)
}

/// Fn 减法（模 n）
#[inline]
pub fn fn_sub(a: &Fn, b: &Fn) -> Fn {
    a.sub(b)
}

/// Fn 乘法（模 n，Montgomery 形式）
#[inline]
pub fn fn_mul(a: &Fn, b: &Fn) -> Fn {
    a.mul(b)
}

/// Fn 取负（模 n）
#[inline]
pub fn fn_neg(a: &Fn) -> Fn {
    a.neg()
}

/// Fn 求逆（Bernstein-Yang 算法，常量时间）
/// 返回 None 当且仅当 a == 0
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
    fn test_fp_add_sub_symmetric() {
        let a = fp_from_bytes(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);
        let b = fp_from_bytes(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
        ]);
        let sum = fp_add(&a, &b);
        let diff = fp_sub(&sum, &b);
        assert_eq!(fp_to_bytes(&diff), fp_to_bytes(&a));
    }

    #[test]
    fn test_fp_mul_by_one() {
        let gx = GX;
        let result = fp_mul(&gx, &Fp::ONE);
        assert_eq!(fp_to_bytes(&result), fp_to_bytes(&gx));
    }

    #[test]
    fn test_fp_inv_roundtrip() {
        let two = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]);
        let inv = fp_inv(&two).expect("2 的逆元应存在");
        assert_eq!(fp_mul(&two, &inv), Fp::ONE);
    }

    #[test]
    fn test_fp_zero_has_no_inv() {
        assert!(fp_inv(&Fp::ZERO).is_none());
    }

    #[test]
    fn test_fp_sqrt_of_four() {
        let four = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ]);
        let root = fp_sqrt(&four).expect("4 应有平方根");
        assert_eq!(fp_square(&root), four);
    }

    #[test]
    fn test_fn_inv_roundtrip() {
        let three = fn_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ]);
        let inv = fn_inv(&three).expect("3^-1 应存在");
        assert_eq!(fn_mul(&three, &inv), Fn::ONE);
    }
}
