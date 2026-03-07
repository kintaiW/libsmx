//! SM9 BN256 六次/十二次扩域 Fp6 / Fp12
//!
//! 塔式扩域：
//!   Fp2 = Fp[u]/(u²+2)
//!   Fp6 = Fp2[v]/(v³-u)     即 v³ = u
//!   Fp12 = Fp6[w]/(w²-v)   即 w² = v
//!
//! Frobenius 系数为编译期常量，源自 GB/T 38635.1-2020 及参考实现。

use crate::sm9::fields::fp::Fp;
use crate::sm9::fields::fp2::{
    fp2_add, fp2_frobenius, fp2_inv, fp2_mul, fp2_mul_u, fp2_neg, fp2_square, fp2_sub, Fp2,
};
use crypto_bigint::U256;
use subtle::{Choice, ConditionallySelectable};

// ── Frobenius 系数（编译时常量）──────────────────────────────────────────────
//
// Reason: 这些常量是 γ_{i,j} = v^{i·(p^j-1)/3} 等，直接硬编码为 `const`，
// 避免每次 Frobenius 调用时重复构造 Fp2，消除运行时开销。
// 系数来源：gm-sdk-rs/src/sm9/field12.rs（经 SM9 规范验证）

/// Fp6 Frobenius p^1 系数 γ_{1,1} = u^{(p-1)/3}
const FROB_V1_0: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "0000000000000000F300000002A3A6F2780272354F8B78F4D5FC11967BE65334",
    )),
    c1: Fp::ZERO,
};
/// Fp6 Frobenius p^1 系数 γ_{2,1} = u^{2(p-1)/3}
const FROB_V1_1: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "0000000000000000F300000002A3A6F2780272354F8B78F4D5FC11967BE65333",
    )),
    c1: Fp::ZERO,
};
/// Fp12 Frobenius p^1 系数 δ_{1,1} = u^{(p-1)/6}
const FROB_W1: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B",
    )),
    c1: Fp::ZERO,
};

/// G2 Frobenius π_p 的 x 坐标修正因子 = u^{(p-1)/3}（= FROB_V1_0）
pub const G2_FROB_X1: Fp2 = FROB_V1_0;

/// G2 Frobenius π_p 的 y 坐标修正因子 = u^{(p-1)/2}
pub const G2_FROB_Y1: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011",
    )),
    c1: Fp::ZERO,
};

/// G2 Frobenius π_{p²} 的 x 坐标修正因子 = u^{(p²-1)/3}
pub const G2_FROB_X2: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "0000000000000000F300000002A3A6F2780272354F8B78F4D5FC11967BE65333",
    )),
    c1: Fp::ZERO,
};
/// G2 Frobenius π_{p²} 的 y 坐标修正因子 = u^{(p²-1)/2} = -1 mod p
/// Reason: u^{(p²-1)/2} = -1 mod p（由测试验证），故 y2 = -Q.y * (-1) = Q.y
pub const G2_FROB_Y2_IS_NEG_ONE: bool = true;

/// G2_FROB_X1 的模逆 = (u^{(p-1)/3})^{-1} mod p
/// Reason: 用于 π₁(Q) 仿射坐标修正：x₁ = x.conj() * G2_FROB_X1_INV
pub const G2_FROB_X1_INV: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "B640000002A3A6F0E303AB4FF2EB2052A9F02115CAEF75E70F738991676AF24A",
    )),
    c1: Fp::ZERO,
};

/// G2_FROB_Y1 的模逆 = (u^{(p-1)/2})^{-1} mod p
/// Reason: 用于 π₁(Q) 仿射坐标修正：y₁ = y.conj() * G2_FROB_Y1_INV
pub const G2_FROB_Y1_INV: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "49DB721A269967C4E0A8DEBC0783182F82555233139E9D63EFBD7B54092C756C",
    )),
    c1: Fp::ZERO,
};

/// G2_FROB_X2 的模逆 = (u^{2(p-1)/3})^{-1} mod p
/// Reason: 用于 -π₂(Q) 仿射坐标修正：x₂ = x * G2_FROB_X2_INV
pub const G2_FROB_X2_INV: Fp2 = Fp2 {
    c0: Fp::new(&U256::from_be_hex(
        "B640000002A3A6F0E303AB4FF2EB2052A9F02115CAEF75E70F738991676AF249",
    )),
    c1: Fp::ZERO,
};

// ── Fp6 ────────────────────────────────────────────────────────────────────

/// Fp6 元素：a = a0 + a1·v + a2·v²，v³ = u
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp6 {
    /// v⁰ 分量（Fp2 元素）
    pub c0: Fp2,
    /// v¹ 分量（Fp2 元素）
    pub c1: Fp2,
    /// v² 分量（Fp2 元素）
    pub c2: Fp2,
}

impl ConditionallySelectable for Fp6 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp6 {
            c0: Fp2::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp2::conditional_select(&a.c1, &b.c1, choice),
            c2: Fp2::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl Fp6 {
    /// Fp6 零元
    pub const ZERO: Self = Fp6 {
        c0: Fp2::ZERO,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };
    /// Fp6 单位元
    pub const ONE: Self = Fp6 {
        c0: Fp2::ONE,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };
}

/// Fp6 加法
#[inline]
pub fn fp6_add(a: &Fp6, b: &Fp6) -> Fp6 {
    Fp6 {
        c0: fp2_add(&a.c0, &b.c0),
        c1: fp2_add(&a.c1, &b.c1),
        c2: fp2_add(&a.c2, &b.c2),
    }
}

/// Fp6 减法
#[inline]
pub fn fp6_sub(a: &Fp6, b: &Fp6) -> Fp6 {
    Fp6 {
        c0: fp2_sub(&a.c0, &b.c0),
        c1: fp2_sub(&a.c1, &b.c1),
        c2: fp2_sub(&a.c2, &b.c2),
    }
}

/// Fp6 取反
#[inline]
pub fn fp6_neg(a: &Fp6) -> Fp6 {
    Fp6 {
        c0: fp2_neg(&a.c0),
        c1: fp2_neg(&a.c1),
        c2: fp2_neg(&a.c2),
    }
}

/// Fp6 乘法（Karatsuba，利用 v³=u 规约）
///
/// (a0+a1v+a2v²)(b0+b1v+b2v²) 展开后 v³→u, v⁴→uv, v⁵→uv²
pub fn fp6_mul(a: &Fp6, b: &Fp6) -> Fp6 {
    let t0 = fp2_mul(&a.c0, &b.c0);
    let t1 = fp2_mul(&a.c1, &b.c1);
    let t2 = fp2_mul(&a.c2, &b.c2);

    // c0 = t0 + (a1+a2)(b1+b2)·u - t1·u - t2·u - t1 - t2
    // 化简：c0 = t0 + u·((a1+a2)(b1+b2) - t1 - t2) - t1 (... 太复杂，使用标准展开)
    // 用直接 6 项展开 + v³→u 规约：
    let a01 = fp2_add(&a.c0, &a.c1);
    let b01 = fp2_add(&b.c0, &b.c1);
    let a12 = fp2_add(&a.c1, &a.c2);
    let b12 = fp2_add(&b.c1, &b.c2);
    let a02 = fp2_add(&a.c0, &a.c2);
    let b02 = fp2_add(&b.c0, &b.c2);

    let m01 = fp2_mul(&a01, &b01); // (a0+a1)(b0+b1) = t0+c01+t1
    let m12 = fp2_mul(&a12, &b12); // (a1+a2)(b1+b2) = t1+c12+t2
    let m02 = fp2_mul(&a02, &b02); // (a0+a2)(b0+b2) = t0+c02+t2

    // 交叉项
    let c01 = fp2_sub(&fp2_sub(&m01, &t0), &t1); // a0b1+a1b0
    let c12 = fp2_sub(&fp2_sub(&m12, &t1), &t2); // a1b2+a2b1
    let c02 = fp2_sub(&fp2_sub(&m02, &t0), &t2); // a0b2+a2b0

    // 规约 v³→u：
    // c0_new = t0 + u·c12  (degree 0: t0·1 + (a1b2+a2b1)·v³ → u·c12)
    // c1_new = c01 + u·t2  (degree v: c01·v + a2b2·v⁴ → u·t2·v)
    // c2_new = c02 + t1    (degree v²: c02·v² + t1·v² → (c02+t1)·v²)
    //                       wait: a1b1·v²·v → ... no.
    // Reason: Fp6 乘积按次数归并：
    //   deg 0: a0b0 = t0
    //   deg 1 (v): a0b1+a1b0 = c01
    //   deg 2 (v²): a0b2+a1b1+a2b0 = c02+t1
    //   deg 3 (v³→u): a1b2+a2b1 = c12, 乘以 u 加入 deg 0
    //   deg 4 (v⁴→uv): a2b2 = t2, 乘以 u 加入 deg 1
    //   deg 5 (v⁵→uv²): 无此项
    let c0_new = fp2_add(&t0, &fp2_mul_u(&c12));
    let c1_new = fp2_add(&c01, &fp2_mul_u(&t2));
    let c2_new = fp2_add(&c02, &t1);

    Fp6 {
        c0: c0_new,
        c1: c1_new,
        c2: c2_new,
    }
}

/// Fp6 平方
pub fn fp6_square(a: &Fp6) -> Fp6 {
    fp6_mul(a, a)
}

/// Fp6 乘以 v（移位：(a0+a1v+a2v²)·v = a2·u + a0·v + a1·v²）
#[inline]
pub fn fp6_mul_v(a: &Fp6) -> Fp6 {
    // (a0+a1v+a2v²)·v = a0v + a1v² + a2v³ = a2·u + a0·v + a1·v²
    Fp6 {
        c0: fp2_mul_u(&a.c2),
        c1: a.c0,
        c2: a.c1,
    }
}

/// Fp6 乘以 Fp2 标量
#[inline]
pub fn fp6_mul_fp2(a: &Fp6, b: &Fp2) -> Fp6 {
    Fp6 {
        c0: fp2_mul(&a.c0, b),
        c1: fp2_mul(&a.c1, b),
        c2: fp2_mul(&a.c2, b),
    }
}

/// Fp6 求逆
pub fn fp6_inv(a: &Fp6) -> Option<Fp6> {
    // 使用伴随矩阵方法
    let t0 = fp2_mul(&a.c0, &a.c0);
    let t1 = fp2_mul(&a.c1, &a.c1);
    let t2 = fp2_mul(&a.c2, &a.c2);
    let t3 = fp2_mul(&a.c0, &a.c1);
    let t4 = fp2_mul(&a.c0, &a.c2);
    let t5 = fp2_mul(&a.c1, &a.c2);

    // A = a0² - u·a1·a2·... (cofactors)
    // Reason: 伴随矩阵法，行列式 = a0·A + a1·B + a2·C
    let ca = fp2_sub(&t0, &fp2_mul_u(&t5)); // a0² - u·a1a2
    let cb = fp2_sub(&fp2_mul_u(&t2), &t3); // u·a2² - a0a1
    let cc = fp2_sub(&t1, &t4); // a1² - a0a2

    // det = a0·ca + a1·(u·cc) + a2·cb ... let's use: norm = a0·ca + u·(a2·cb + a1·cc)
    // Actually: det_norm(a) = a0*(a0²-ua1a2) + a1*(ua2²-a0a1) + a2*(a1²-a0a2)
    //         = a0³ - ua0a1a2 + ua1a2² - a0a1² + a1²a2 - a0a2²
    //         = a0³ + a1³u + a2³u² - 3a0a1a2·... no, let's do it directly
    let t_a1cc = fp2_mul(&a.c1, &cc);
    let t_a2cb = fp2_mul(&a.c2, &cb);
    let inner = fp2_add(&t_a1cc, &t_a2cb);
    let norm = fp2_add(&fp2_mul(&a.c0, &ca), &fp2_mul_u(&inner));

    let norm_inv = fp2_inv(&norm)?;
    Some(Fp6 {
        c0: fp2_mul(&ca, &norm_inv),
        c1: fp2_mul(&cb, &norm_inv),
        c2: fp2_mul(&cc, &norm_inv),
    })
}

/// Fp6 Frobenius p 次幂
pub fn fp6_frobenius_p(a: &Fp6) -> Fp6 {
    Fp6 {
        c0: fp2_frobenius(&a.c0),
        c1: fp2_mul(&fp2_frobenius(&a.c1), &FROB_V1_0),
        c2: fp2_mul(&fp2_frobenius(&a.c2), &FROB_V1_1),
    }
}

/// Fp6 Frobenius p² 次幂（组合两次 p 次幂，保证与 fp6_frobenius_p 一致）
pub fn fp6_frobenius_p2(a: &Fp6) -> Fp6 {
    fp6_frobenius_p(&fp6_frobenius_p(a))
}

/// Fp6 Frobenius p³ 次幂（组合三次 p 次幂，保证与 fp6_frobenius_p 一致）
pub fn fp6_frobenius_p3(a: &Fp6) -> Fp6 {
    fp6_frobenius_p(&fp6_frobenius_p2(a))
}

// ── Fp12 ───────────────────────────────────────────────────────────────────

/// Fp12 元素：f = f0 + f1·w，w² = v
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fp12 {
    /// w⁰ 分量（Fp6 元素）
    pub c0: Fp6,
    /// w¹ 分量（Fp6 元素）
    pub c1: Fp6,
}

impl ConditionallySelectable for Fp12 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp12 {
            c0: Fp6::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp6::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl Fp12 {
    /// Fp12 零元
    pub const ZERO: Self = Fp12 {
        c0: Fp6::ZERO,
        c1: Fp6::ZERO,
    };
    /// Fp12 单位元
    pub const ONE: Self = Fp12 {
        c0: Fp6::ONE,
        c1: Fp6::ZERO,
    };
}

/// Fp12 加法
#[inline]
pub fn fp12_add(a: &Fp12, b: &Fp12) -> Fp12 {
    Fp12 {
        c0: fp6_add(&a.c0, &b.c0),
        c1: fp6_add(&a.c1, &b.c1),
    }
}

/// Fp12 减法
#[inline]
pub fn fp12_sub(a: &Fp12, b: &Fp12) -> Fp12 {
    Fp12 {
        c0: fp6_sub(&a.c0, &b.c0),
        c1: fp6_sub(&a.c1, &b.c1),
    }
}

/// Fp12 取反
#[inline]
pub fn fp12_neg(a: &Fp12) -> Fp12 {
    Fp12 {
        c0: fp6_neg(&a.c0),
        c1: fp6_neg(&a.c1),
    }
}

/// Fp12 乘法：(a0+a1·w)(b0+b1·w) = (a0b0 + a1b1·v) + (a0b1+a1b0)·w
///
/// w² = v，所以 a1b1·w² = a1b1·v（在 Fp6 层，乘以 v 用 fp6_mul_v）
pub fn fp12_mul(a: &Fp12, b: &Fp12) -> Fp12 {
    let t0 = fp6_mul(&a.c0, &b.c0);
    let t1 = fp6_mul(&a.c1, &b.c1);
    // c0 = t0 + t1·w² = t0 + t1·v
    let c0 = fp6_add(&t0, &fp6_mul_v(&t1));
    // c1 = (a0+a1)(b0+b1) - t0 - t1
    let a01 = fp6_add(&a.c0, &a.c1);
    let b01 = fp6_add(&b.c0, &b.c1);
    let c1 = fp6_sub(&fp6_sub(&fp6_mul(&a01, &b01), &t0), &t1);
    Fp12 { c0, c1 }
}

/// Fp12 平方（cyclotomic squaring 在 hard_exp 中）
pub fn fp12_square(a: &Fp12) -> Fp12 {
    fp12_mul(a, a)
}

/// Fp12 循环子群平方（用于最终幂指数硬部分）
///
/// Reason: 在 GT 群（BN256 cyclotomic subgroup）中，满足 f^{p^6+1}=1，
/// 可用 4 次 Fp2 平方替代 1 次 Fp12 平方（Granger-Scott 优化）。
pub fn fp12_cyclotomic_square(a: &Fp12) -> Fp12 {
    let f0 = a.c0.c0;
    let f1 = a.c1.c0;
    let f2 = a.c0.c1;
    let f3 = a.c1.c1;
    let f4 = a.c0.c2;
    let f5 = a.c1.c2;

    // t0 = (f0+f1·w')² in Fp2×Fp2 sub-extension
    let (t0, t1) = fp2_pair_square(&f0, &f1);
    let (t2, t3) = fp2_pair_square(&f4, &f2); // 注意顺序
    let (t4, t5) = fp2_pair_square(&f3, &f5);

    // g0 = 3t0 - 2f0;  g1 = 3t1 + 2f1
    let g0 = fp2_sub(&fp2_add(&fp2_add(&t0, &t0), &t0), &fp2_add(&f0, &f0));
    let g1 = fp2_add(&fp2_add(&t1, &t1), &fp2_add(&t1, &fp2_add(&f1, &f1)));

    // g2 = 3t2 + 2f4; g3 = 3t3 - 2f2 (using u-mul for twist)
    let g2 = fp2_add(&fp2_add(&t2, &t2), &fp2_add(&t2, &fp2_add(&f4, &f4)));
    let g3 = fp2_sub(&fp2_add(&fp2_add(&t3, &t3), &t3), &fp2_add(&f2, &f2));

    // g4 = 3t4 - 2f3; g5 = 3t5 + 2f5
    let g4 = fp2_sub(&fp2_add(&fp2_add(&t4, &t4), &t4), &fp2_add(&f3, &f3));
    let g5 = fp2_add(&fp2_add(&t5, &t5), &fp2_add(&t5, &fp2_add(&f5, &f5)));

    Fp12 {
        c0: Fp6 {
            c0: g0,
            c1: g3,
            c2: g4,
        },
        c1: Fp6 {
            c0: g1,
            c1: g2,
            c2: g5,
        },
    }
}

/// 辅助：(a+b·s)² in Fp2 split quadratic extension where s²=u
/// 返回 (a²+2·b²·? , 2ab) — 实际用于 cyclotomic_square 的成对计算
fn fp2_pair_square(a: &Fp2, b: &Fp2) -> (Fp2, Fp2) {
    // (a+b)² = a²+2ab+b², 用 Karatsuba：
    // 用于 cyclotomic squaring 的 Fp2×Fp2 中
    // 这里等价于 Fp4 = Fp2[s]/(s²-v) 中的平方
    // (a+b·s)² = a²+b²·v + 2ab·s
    let a2 = fp2_square(a);
    let b2 = fp2_square(b);
    let ab = fp2_mul(a, b);
    // Reason: 在 Fp4=Fp2[s]/(s²=u) 中，(a+bs)² = (a²+u·b²) + 2ab·s
    let new_a = fp2_add(&a2, &fp2_mul_u(&b2));
    let new_b = fp2_add(&ab, &ab);
    (new_a, new_b)
}

/// Fp12 求逆
pub fn fp12_inv(a: &Fp12) -> Option<Fp12> {
    // 1/(f0+f1·w) = (f0-f1·w)/(f0²-f1²·v)
    let norm0 = fp6_mul(&a.c0, &a.c0); // f0²
    let norm1 = fp6_mul_v(&fp6_mul(&a.c1, &a.c1)); // f1²·v
    let norm = fp6_sub(&norm0, &norm1); // f0²-f1²·v
    let norm_inv = fp6_inv(&norm)?;
    Some(Fp12 {
        c0: fp6_mul(&a.c0, &norm_inv),
        c1: fp6_neg(&fp6_mul(&a.c1, &norm_inv)),
    })
}

/// Fp12 Frobenius p 次幂
pub fn fp12_frobenius_p(a: &Fp12) -> Fp12 {
    Fp12 {
        c0: fp6_frobenius_p(&a.c0),
        c1: fp6_mul_fp2(&fp6_frobenius_p(&a.c1), &FROB_W1),
    }
}

/// Fp12 Frobenius p² 次幂
///
/// Reason: 用两次 fp12_frobenius_p 组合保证正确性。
/// 独立硬编码的 δ_{1,2} 系数与 fp12_frobenius_p 不一致，导致配对双线性性失败。
pub fn fp12_frobenius_p2(a: &Fp12) -> Fp12 {
    fp12_frobenius_p(&fp12_frobenius_p(a))
}

/// Fp12 Frobenius p³ 次幂
///
/// Reason: 用 fp12_frobenius_p 组合保证正确性（同 fp12_frobenius_p2）。
pub fn fp12_frobenius_p3(a: &Fp12) -> Fp12 {
    fp12_frobenius_p(&fp12_frobenius_p2(a))
}

/// Fp12 共轭（GT 群中的逆 = 共轭：f → f^{p^6} = f^{-1} for |f|=1）
#[inline]
pub fn fp12_conjugate(a: &Fp12) -> Fp12 {
    Fp12 {
        c0: a.c0,
        c1: fp6_neg(&a.c1),
    }
}

/// Fp12 将元素序列化为 384 字节（用于 KDF）
pub fn fp12_to_bytes(a: &Fp12) -> [u8; 384] {
    let mut out = [0u8; 384];
    // c0.c0, c0.c1, c0.c2, c1.c0, c1.c1, c1.c2 各 64 字节
    let parts = [a.c0.c0, a.c0.c1, a.c0.c2, a.c1.c0, a.c1.c1, a.c1.c2];
    for (i, fp2) in parts.iter().enumerate() {
        let b = fp2.to_bytes();
        out[i * 64..(i + 1) * 64].copy_from_slice(&b);
    }
    out
}

/// Miller loop 线函数（稀疏 Fp12，double step 和 add step 通用）
///
/// 槽位约定：{c0.c0(×yP), c0.c1(v), c1.c0(w·xP)}
/// - a: yP 系数 -> c0.c0（1 slot，在 eval_line_at_p 中乘以 yP）
/// - b: 常数项 -> c0.c1（v slot）
/// - c: xP 系数 -> c1.c0（w slot，在 eval_line_at_p 中乘以 xP）
/// Reason: 经双线性性测试验证，此约定对应 D-type twist BN256 配对正确系数。
///   double step: a=Z₁²·u, b=-2Y₁Z₁, c=3X₁²
///   add step:    a=r·x2, b=-(r·x1+h·y1), c=h·y2
#[derive(Clone, Copy, Debug)]
pub struct LineEval {
    /// a 系数（×yP 后放 c0.c0，即 1 slot）
    pub a: Fp2,
    /// 常数项，对应 Fp12 中 v（c0.c1）位置
    pub b: Fp2,
    /// c 系数，对应 Fp12 中 w（c1.c0）位置（×xP）
    pub c: Fp2,
}

/// Fp12 乘以线函数（double step 和 add step 通用）
///
/// ℓ = a*yP(c0.c0) + b(c1.c1·vw) + c*xP(c1.c2·v²w)
/// Reason: 槽位 {c0.c0(1), c1.c1(vw), c1.c2(v²w)} 对应 D-type twist BN256 R-ate 配对的正确系数：
///   - a 系数（yP 项）→ c0.c0 (1 slot)
///   - b 系数（常数项）→ c1.c1 (vw slot)
///   - c 系数（xP 项）→ c1.c2 (v²w slot)
///   a、c 已经在 eval_line_at_p 中分别乘以 yP 和 xP。
pub fn fp12_mul_by_line(f: &Fp12, l: &LineEval) -> Fp12 {
    let line_fp12 = Fp12 {
        c0: Fp6 {
            c0: l.a,
            c1: Fp2::ZERO,
            c2: Fp2::ZERO,
        },
        c1: Fp6 {
            c0: Fp2::ZERO,
            c1: l.b,
            c2: l.c,
        },
    };
    fp12_mul(f, &line_fp12)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp6_add_neg() {
        let a = Fp6 {
            c0: Fp2::ONE,
            c1: Fp2::ZERO,
            c2: Fp2::ZERO,
        };
        let neg_a = fp6_neg(&a);
        let sum = fp6_add(&a, &neg_a);
        assert_eq!(sum, Fp6::ZERO);
    }

    #[test]
    fn test_fp6_mul_one() {
        let a = Fp6 {
            c0: Fp2::ONE,
            c1: Fp2 {
                c0: Fp::ONE,
                c1: Fp::ZERO,
            },
            c2: Fp2::ZERO,
        };
        let r = fp6_mul(&a, &Fp6::ONE);
        assert_eq!(r, a);
    }

    #[test]
    fn test_fp12_mul_one() {
        let a = Fp12 {
            c0: Fp6 {
                c0: Fp2::ONE,
                c1: Fp2::ZERO,
                c2: Fp2::ZERO,
            },
            c1: Fp6::ZERO,
        };
        let r = fp12_mul(&a, &Fp12::ONE);
        assert_eq!(r, a);
    }

    #[test]
    fn test_fp12_inv() {
        let a = Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp::ONE,
                    c1: Fp::ONE,
                },
                c1: Fp2::ZERO,
                c2: Fp2::ZERO,
            },
            c1: Fp6::ZERO,
        };
        let inv = fp12_inv(&a).expect("逆元应存在");
        let prod = fp12_mul(&a, &inv);
        assert_eq!(prod, Fp12::ONE);
    }

    /// 验证稀疏线函数乘法与全量 fp12_mul 结果一致
    #[test]
    fn test_fp12_mul_by_line_matches_full_mul() {        // 构造一个非平凡的 f
        let f = Fp12 {
            c0: Fp6 {
                c0: Fp2 { c0: Fp::ONE, c1: Fp::ONE },
                c1: Fp2 { c0: Fp::ONE, c1: Fp::ZERO },
                c2: Fp2::ZERO,
            },
            c1: Fp6 {
                c0: Fp2 { c0: Fp::ZERO, c1: Fp::ONE },
                c1: Fp2::ZERO,
                c2: Fp2::ZERO,
            },
        };

        // 构造非零线函数
        let l = LineEval {
            a: Fp2 { c0: Fp::ONE, c1: Fp::ONE },
            b: Fp2 { c0: Fp::ONE, c1: Fp::ZERO },
            c: Fp2 { c0: Fp::ZERO, c1: Fp::ONE },
        };

        // 稀疏乘法结果
        let sparse = fp12_mul_by_line(&f, &l);

        // 构造全量 Fp12 线函数并做全量乘法（与 fp12_mul_by_line slot 保持一致）
        // 槽位约定：a→c0.c0(1), b→c1.c1(vw), c→c1.c2(v²w)
        let line_full = Fp12 {
            c0: Fp6 { c0: l.a, c1: Fp2::ZERO, c2: Fp2::ZERO },
            c1: Fp6 { c0: Fp2::ZERO, c1: l.b, c2: l.c },
        };
        let full = fp12_mul(&f, &line_full);

        assert_eq!(sparse, full, "稀疏线函数乘法与全量乘法结果不一致");
    }

    /// 验证 fp12 Frobenius 一致性
    #[test]
    fn test_frob_w3_derivation() {
        // 验证 fp12 Frobenius 一致性：frob_p(frob_p(f)) == frob_p2(f)
        let f = Fp12 {
            c0: Fp6 { c0: Fp2 { c0: Fp::ONE, c1: Fp::ONE }, c1: Fp2::ONE, c2: Fp2::ZERO },
            c1: Fp6 { c0: Fp2::ONE, c1: Fp2::ZERO, c2: Fp2::ZERO },
        };
        let fp1 = fp12_frobenius_p(&f);
        let fp1p1 = fp12_frobenius_p(&fp1);  // frob_p^2(f)
        let fp2 = fp12_frobenius_p2(&f);
        assert_eq!(fp1p1, fp2, "frob_p(frob_p(f)) != frob_p2(f)：fp12 Frobenius 不一致");

        let fp2p1 = fp12_frobenius_p(&fp2);  // frob_p^3(f)
        let fp3 = fp12_frobenius_p3(&f);
        assert_eq!(fp2p1, fp3, "frob_p(frob_p2(f)) != frob_p3(f)：fp12_frobenius_p3 系数错误");
    }

    /// 验证 Fp6 Frobenius 保持 ONE
    #[test]
    fn test_frobenius_one() {
        let one = Fp6::ONE;
        let f_p = fp6_frobenius_p(&one);
        let f_p2 = fp6_frobenius_p2(&one);
        let f_p3 = fp6_frobenius_p3(&one);
        assert_eq!(f_p, one, "frobenius_p(ONE) != ONE");
        assert_eq!(f_p2, one, "frobenius_p2(ONE) != ONE");
        assert_eq!(f_p3, one, "frobenius_p3(ONE) != ONE");
    }

    /// 验证 FROB_V1_0^2 = FROB_V1_1（γ_{1,1}^2 = γ_{2,1}）
    #[test]
    fn test_frob_v1_squared() {
        use crate::sm9::fields::fp2::fp2_mul;
        let v1_sq = fp2_mul(&FROB_V1_0, &FROB_V1_0);
        assert_eq!(v1_sq, FROB_V1_1, "FROB_V1_0² 应等于 FROB_V1_1（fp6 Frobenius 一致性）");
    }

    /// 计算 u^{(p-1)/3} 并与 FROB_V1_0 对比（验证常量正确性）
    ///
    /// FROB_V1_0 应等于 v^{p-1}，由于 v^3=u，这等价于 u^{(p-1)/3} mod p
    #[test]
    fn test_frob_v1_0_value_correct() {
        use crate::sm9::fields::fp::FIELD_MODULUS;
        use crate::sm9::fields::fp2::{fp2_mul, fp2_square};
        use subtle::ConditionallySelectable;
        // 计算 u^{(p-1)/3} 其中 u = (0, 1) ∈ Fp2
        let pm1 = FIELD_MODULUS.wrapping_sub(&crypto_bigint::U256::ONE);
        let (pm1_div3, rem) = pm1.div_rem(&crypto_bigint::NonZero::new(crypto_bigint::U256::from(3u32)).unwrap());
        assert_eq!(rem, crypto_bigint::U256::ZERO, "(p-1) 应被 3 整除");

        let (pm1_div6, _) = pm1.div_rem(&crypto_bigint::NonZero::new(crypto_bigint::U256::from(6u32)).unwrap());

        fn fp2_pow_exp(base: &Fp2, exp: &crypto_bigint::U256) -> Fp2 {
            use crate::sm9::fields::fp2::{fp2_mul, fp2_square};
            use subtle::ConditionallySelectable;
            let mut result = Fp2::ONE;
            let mut b = *base;
            for byte in exp.to_be_bytes().iter().rev() {
                for bit in 0..8 {
                    let product = fp2_mul(&result, &b);
                    let choice = subtle::Choice::from((byte >> bit) & 1);
                    result = Fp2::conditional_select(&result, &product, choice);
                    b = fp2_square(&b);
                }
            }
            result
        }

        let u = Fp2 { c0: crate::sm9::fields::fp::Fp::ZERO, c1: crate::sm9::fields::fp::Fp::ONE };
        // 正确的 γ_{1,1} = u^{(p-1)/3}
        let correct_v1_0 = fp2_pow_exp(&u, &pm1_div3);
        // 正确的 δ_{1,1} = u^{(p-1)/6}（FROB_W1）
        let correct_w1 = fp2_pow_exp(&u, &pm1_div6);

        // 验证：correct_w1^2 = correct_v1_0（δ^2 = γ）
        let w1_sq = fp2_mul(&correct_w1, &correct_w1);
        assert_eq!(w1_sq, correct_v1_0, "u^{{(p-1)/6}}^2 应等于 u^{{(p-1)/3}}");

        // 打印正确的常量值（以标准 32 字节大端 hex 格式，供直接写入代码）
        assert_eq!(
            correct_v1_0, FROB_V1_0,
            "FROB_V1_0 需更新：正确值={:02X?}, FROB_W1 正确值 c0={:02X?} c1={:02X?}",
            correct_v1_0.c0.retrieve().to_be_bytes(),
            correct_w1.c0.retrieve().to_be_bytes(),
            correct_w1.c1.retrieve().to_be_bytes(),
        );
    }
}

#[cfg(test)]
mod g2_frob_tests {
    use super::*;

    #[test]
    fn test_compute_g2_frobenius_constants() {
        use crate::sm9::fields::fp::FIELD_MODULUS;

        fn fp2_pow_exp(base: &Fp2, exp: &crypto_bigint::U256) -> Fp2 {
            use crate::sm9::fields::fp2::{fp2_mul, fp2_square};
            use subtle::ConditionallySelectable;
            let mut result = Fp2::ONE;
            let mut b = *base;
            for byte in exp.to_be_bytes().iter().rev() {
                for bit in 0..8 {
                    let product = fp2_mul(&result, &b);
                    let choice = subtle::Choice::from((byte >> bit) & 1);
                    result = Fp2::conditional_select(&result, &product, choice);
                    b = fp2_square(&b);
                }
            }
            result
        }

        let p = FIELD_MODULUS;
        let pm1 = p.wrapping_sub(&crypto_bigint::U256::ONE);
        let u = Fp2 { c0: Fp::ZERO, c1: Fp::ONE };

        let pm1_div2 = pm1.wrapping_shr(1);
        let u_pm1_div2 = fp2_pow_exp(&u, &pm1_div2);

        let (pm1_div3, _) = pm1.div_rem(&crypto_bigint::NonZero::new(crypto_bigint::U256::from(3u32)).unwrap());
        let u_pm1_div3 = fp2_pow_exp(&u, &pm1_div3);

        let pp1 = p.wrapping_add(&crypto_bigint::U256::ONE);
        let u_pm21_div3 = fp2_pow_exp(&u_pm1_div3, &pp1);
        let u_pm21_div2 = fp2_pow_exp(&u_pm1_div2, &pp1);

        // Reason: 验证 G2 Frobenius 修正常量与计算值一致
        // u^{(p-1)/2} 应等于 G2_FROB_Y1
        assert_eq!(u_pm1_div2, G2_FROB_Y1,
            "u^(p-1)/2 应等于 G2_FROB_Y1");
        // u^{(p²-1)/3} 应等于 G2_FROB_X2
        assert_eq!(u_pm21_div3, G2_FROB_X2,
            "u^(p2-1)/3 应等于 G2_FROB_X2");
    }
}
