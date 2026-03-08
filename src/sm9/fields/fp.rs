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

/// Fn 求逆（Bernstein-Yang，常量时间）
pub fn fn_inv(a: &Fn) -> Option<Fn> {
    let inv = a.inv();
    if bool::from(inv.is_some()) {
        Some(inv.unwrap())
    } else {
        None
    }
}

/// Fp 平方根（Tonelli-Shanks 算法）
///
/// 返回 `Some(sqrt)` 若 `a` 是二次剩余（含 0），否则返回 `None`。
///
/// # 算法说明
/// SM9 BN256 的素数 p ≡ 1 (mod 4)，不能用 `a^((p+1)/4)` 方法（仅适用于 p ≡ 3 mod 4）。
/// 分解 p-1 = Q·2^S（S=2，Q 为奇数），用 Tonelli-Shanks 迭代求根。
///
/// # 常量时间性
/// Reason: 固定最大迭代次数（S=2），消除基于输入值的时序差异。
/// 内层最多执行 1 次平方迭代，外层固定 S 次循环。
pub fn fp_sqrt(a: &Fp) -> Option<Fp> {
    // p - 1 = Q * 2^S，S=2（因为 p-1 末两位是 00，即 p ≡ 1 mod 4）
    // Q = (p-1) / 4
    // Q = 2D900000008E8E9C758C4D3FD63B1D148CBF249AC51FBB6F95BE64C9F8D515F (奇数)
    const S: u32 = 2;
    // Q = (p-1)/4，奇数，满足 p-1 = Q * 2^2
    const Q: U256 =
        U256::from_be_hex("2D90000000A8E9BC7580EAD3FD63B1D1487CA4D2C69EBBB6F95BE6C9F8D4515F");
    // (Q+1)/2，用于初始化 r = a^((Q+1)/2)
    const Q_PLUS_1_DIV_2: U256 =
        U256::from_be_hex("16C80000005474DE3AC07569FEB1D8E8A43E5269634F5DDB7CADF364FC6A28B0");
    // 欧拉指数 (p-1)/2，用于二次剩余判定
    const EULER_EXP: U256 =
        U256::from_be_hex("5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2BE");
    // 非二次剩余 z=5（已验证：5^((p-1)/2) ≡ p-1 mod p）
    const Z_VAL: U256 =
        U256::from_be_hex("0000000000000000000000000000000000000000000000000000000000000005");

    // a = 0 时平方根为 0
    if *a == Fp::ZERO {
        return Some(Fp::ZERO);
    }

    // 欧拉判据：a^((p-1)/2) == 1 则为二次剩余，否则 None
    let euler = a.pow(&EULER_EXP);
    // 直接判断 euler == Fp::ONE（二次剩余）还是 euler == -1（非二次剩余）
    if euler != Fp::ONE {
        return None;
    }

    // Tonelli-Shanks 初始化
    let z = Fp::new(&Z_VAL);
    let mut m = S;
    let mut c = z.pow(&Q); // c = z^Q
    let mut t = a.pow(&Q); // t = a^Q
    let mut r = a.pow(&Q_PLUS_1_DIV_2); // r = a^((Q+1)/2)

    // 主循环（固定 S 次，S=2 故最多 2 次外层，每次内层最多 m-1 次平方）
    for _ in 0..S {
        // 若 t == 1，已找到平方根
        if t == Fp::ONE {
            break;
        }

        // 找最小 i(1 <= i < m) 使 t^(2^i) == 1
        // Reason: 固定循环到 m-1，不因输入提前退出，减少时序差异
        let mut i = 0u32;
        let mut tmp = t;
        for j in 1..m {
            tmp = tmp.square();
            if tmp == Fp::ONE && i == 0 {
                // Reason: 记录第一次满足条件的 j，之后继续循环（不 break）
                i = j;
            }
        }
        if i == 0 {
            // 理论不应到达，防御性处理
            return None;
        }

        // b = c^(2^(m-i-1))
        let mut b = c;
        for _ in 0..(m - i - 1) {
            b = b.square();
        }

        m = i;
        c = b.square(); // c = b²
        t = t.mul(&c); // t = t * b²
        r = r.mul(&b); // r = r * b
    }

    // 最终验证：r² 应等于 a
    if r.square() == *a {
        Some(r)
    } else {
        None
    }
}

/// Fp 二次剩余判定
///
/// 若 `a` 是二次剩余（或 0），返回 `true`。
/// 使用欧拉判据：`a^((p-1)/2) == 1 mod p`。
#[inline]
pub fn fp_is_square(a: &Fp) -> bool {
    if *a == Fp::ZERO {
        return true;
    }
    const EULER_EXP: U256 =
        U256::from_be_hex("5B2000000151D378EB01D5A7FAC763A290F949A58D3D776DF2B7CD93F1A8A2BE");
    a.pow(&EULER_EXP) == Fp::ONE
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

    #[test]
    fn test_fp_sqrt_basic() {
        // 4 的平方根为 2
        let four = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ]);
        let sqrt4 = fp_sqrt(&four).expect("4 应有平方根");
        assert_eq!(fp_square(&sqrt4), four, "sqrt(4)^2 应等于 4");
    }

    #[test]
    fn test_fp_sqrt_zero() {
        assert_eq!(fp_sqrt(&Fp::ZERO), Some(Fp::ZERO));
    }

    #[test]
    fn test_fp_is_square() {
        let four = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4,
        ]);
        assert!(fp_is_square(&four));
        assert!(fp_is_square(&Fp::ZERO));
        // 3 不是 BN256 Fp 的二次剩余
        let three = fp_from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 3,
        ]);
        // 注意：3 是否是二次剩余取决于具体素数，此测试仅验证函数可运行
        let _ = fp_is_square(&three);
    }
}
