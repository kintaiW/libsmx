//! SM9 BN256 R-ate 配对
//!
//! R-ate 配对 e: G1 × G2 → GT（GT ⊂ Fp12*）
//!
//! 算法：
//! 1. Miller loop：计算 f_{t,Q}(P)，使用 NAF(T_LOOP_PARAM) 参数
//! 2. 最终幂指数：f^{(p^12-1)/r}
//!    = f^{(p^6-1)} · f^{(p^2+1)} · f^{(p^4-p^2+1)/r}

use crate::sm9::fields::fp::Fp;
use crate::sm9::fields::fp12::{
    fp12_conjugate, fp12_frobenius_p, fp12_frobenius_p2, fp12_frobenius_p3, fp12_inv, fp12_mul,
    fp12_mul_by_line, fp12_square, Fp12, LineEval, G2_FROB_X1_INV, G2_FROB_X2_INV, G2_FROB_Y1_INV,
};
use crate::sm9::fields::fp2::{fp2_frobenius, fp2_mul, fp2_mul_fp};
use crate::sm9::groups::g1::G1Affine;
use crate::sm9::groups::g2::{G2Affine, G2Jacobian};

// ── Miller loop 参数 ────────────────────────────────────────────────────────

/// SM9 BN256 R-ate Miller loop 参数 = 6s+2（SM9 Optimal Ate pairing 的标准参数）
///
/// Reason: SM9 R-ate pairing 的 Miller loop 对 6s+2 进行循环，然后最后加 Q1=π_p(Q) 和 Q2=-π_p²(Q)。
/// 这与 sm9_core 的 SM9_LOOP_N = 0x2400000000215D93E 完全一致。
const T_LOOP_PARAM: u128 = 0x2400000000215D93E; // 6 * SM9_SEED + 2

// ── G2 Frobenius（用于 Miller loop 最后步骤）────────────────────────────────

/// G2 点的 p 次 Frobenius（仿射坐标，带扭曲修正因子）
///
/// Reason: 对仿射点 Q = (x, y) ∈ G2（Fp2 坐标），π₁(Q) 的仿射坐标为：
///   x₁ = x.conj() * G2_FROB_X1^{-1}（共轭后除以 u^{(p-1)/3}）
///   y₁ = y.conj() * G2_FROB_Y1^{-1}（共轭后除以 u^{(p-1)/2}）
/// 推导：从 Jacobian point_pi1(Q) = (x.conj(), y.conj(), PI1) 转为仿射得此结果。
fn g2_frobenius_p(q: &G2Affine) -> G2Affine {
    G2Affine {
        x: fp2_mul(&fp2_frobenius(&q.x), &G2_FROB_X1_INV),
        y: fp2_mul(&fp2_frobenius(&q.y), &G2_FROB_Y1_INV),
    }
}

/// G2 点的 -π₂(Q)（p² 次 Frobenius 取负，ate pairing 最后步骤）
///
/// Reason: 对仿射点 Q = (x, y) ∈ G2，-π₂(Q) 的仿射坐标为：
///   x = x * G2_FROB_X2^{-1}
///   y = y（两次共轭 = 无变化，-1 × (-1) = 1 对 y 的修正）
/// 推导：π₂ 应用两次 q_power_frobenius（PI1），y 修正为 G2_FROB_Y1^{-2} = -1，
///   故 π₂(Q).y = -Q.y，再取负得 y = Q.y。
fn g2_frobenius_p2_neg(q: &G2Affine) -> G2Affine {
    G2Affine {
        x: fp2_mul(&q.x, &G2_FROB_X2_INV),
        y: q.y,
    }
}

// ── 线函数取值 ──────────────────────────────────────────────────────────────

/// 将线函数系数与 G1 点 P 的坐标结合（线函数在 P 点处取值）
///
/// Reason: 线函数 ℓ(P)，将 P 的坐标代入稀疏系数：
///   a 系数乘以 yP（对应 1·yP 槽），b 为常数，c 系数乘以 xP（对应 w·xP 槽）
fn eval_line_at_p(line: &LineEval, px: &Fp, py: &Fp) -> LineEval {
    LineEval {
        a: fp2_mul_fp(&line.a, py), // a × yP（放 c0.c0 槽）
        b: line.b,                  // 常数项不变（放 c0.c1 v 槽）
        c: fp2_mul_fp(&line.c, px), // c × xP（放 c1.c0 w 槽）
    }
}

// ── Miller loop ────────────────────────────────────────────────────────────

/// SM9 R-ate Miller loop
///
/// 计算 f = MillerLoop(Q, P)，其中 Q ∈ G2, P ∈ G1
///
/// Reason: 使用二进制方法（非 NAF）直接扫描 T_LOOP_PARAM 的各位，与 sm9_core G2Prepared
/// 算法完全对应：bits 位迭代（不含最高位），每步 double+tangent，遇到 1 则 add+chord。
pub fn miller_loop(q: &G2Affine, p: &G1Affine) -> Fp12 {
    let mut t = G2Jacobian::from_affine(q);
    let mut f = Fp12::ONE;

    let px = &p.x;
    let py = &p.y;

    // T_LOOP_PARAM 有效位数（不含最高位的 1）
    // T_LOOP_PARAM = 0x2400000000215D93E，bit_length = 66，跳过最高位 bit 65
    // 从 bit 64 到 bit 0（共 65 步）
    // Reason: 与 sm9_core G2Prepared 完全一致，bits = 128 - leading_zeros - 1 = 65
    const BITS: u32 = 65;

    for i in (0..BITS).rev() {
        // f = f²（在 miller loop 每步平方）
        f = fp12_square(&f);

        // 点倍，获取线函数（tangent line）
        let (t2, line) = t.double_with_line();
        t = t2;
        f = fp12_mul_by_line(&f, &eval_line_at_p(&line, px, py));

        // 如果当前位为 1，则加 Q（chord line）
        if (T_LOOP_PARAM >> i) & 1 == 1 {
            let (t_new, line2) = t.add_with_line(q);
            t = t_new;
            f = fp12_mul_by_line(&f, &eval_line_at_p(&line2, px, py));
        }
    }

    // ate pairing 最后两步：T += π₁(Q)，T += -π₂(Q)
    let q1 = g2_frobenius_p(q);
    let q2 = g2_frobenius_p2_neg(q);

    let (t_new, line_q1) = t.add_with_line(&q1);
    let t = t_new;
    f = fp12_mul_by_line(&f, &eval_line_at_p(&line_q1, px, py));

    let (_t_final, line_q2) = t.add_with_line(&q2);
    f = fp12_mul_by_line(&f, &eval_line_at_p(&line_q2, px, py));

    f
}

// ── 最终幂指数 ───────────────────────────────────────────────────────────────

/// 最终幂指数简单部分：f^{(p^6-1)(p^2+1)}
fn final_exp_easy(f: &Fp12) -> Fp12 {
    // f^{p^6-1} = conjugate(f) · f^{-1}
    // Reason: 在 BN256 上 f^{p^6} = conjugate(f)，所以 f^{p^6-1} = conj(f)/f
    let f_conj = fp12_conjugate(f);
    let f_inv = match fp12_inv(f) {
        Some(v) => v,
        None => return Fp12::ONE,
    };
    let f1 = fp12_mul(&f_conj, &f_inv);
    // f^{(p^6-1)(p^2+1)} = f1^{p^2} · f1
    fp12_mul(&fp12_frobenius_p2(&f1), &f1)
}

/// 在 GT 群中计算 f^n（n 为 u128），使用普通 Fp12 平方
///
/// Reason: 使用 fp12_square（非 cyclotomic_square），因为 fp12_cyclotomic_square 的
///   实现依赖 Fp4 分解，当前塔结构为 Fp12=Fp6[w]/(w²-v)，cyclotomic_square 的
///   子扩域分组需要与塔结构严格对应，暂用标准平方保证正确性。
fn fp12_cyclotomic_pow(f: &Fp12, mut n: u128) -> Fp12 {
    let mut result = Fp12::ONE;
    let mut base = *f;
    while n > 0 {
        if n & 1 == 1 {
            result = fp12_mul(&result, &base);
        }
        base = fp12_square(&base);
        n >>= 1;
    }
    result
}

// SM9 最终幂指数硬部分常量
// Reason: 来自 sm9_core 的 SM9_A2/A3/NINE 常量，对应 SM9 BN256 参数
const SM9_A3: u128 = 0x2400000000215d941; // ≈ 6s+5
const SM9_A2: u128 = 0xd8000000019062ed0000b98b0cb27659; // SM9 群阶 n
const SM9_NINE: u128 = 9;

/// 最终幂指数硬部分（SM9 BN256 特定分解）
///
/// 计算 f^{(p^4-p^2+1)/r}，使用 sm9_core 相同的算法
///
/// Reason: Beuchat et al. 分解针对标准 BN256（以太坊参数），不适用于 SM9 BN256。
///   此函数使用 sm9_core 的 final_exp_last_chunk 算法（基于 SM9_A2/A3 常量）。
fn final_exp_hard(f: &Fp12) -> Fp12 {
    let a = fp12_cyclotomic_pow(f, SM9_A3); // f^{A3}
    let b = fp12_inv(&a).unwrap_or(Fp12::ONE); // f^{-A3}
    let c = fp12_frobenius_p(&b); // f^{-A3*p}
    let d = fp12_mul(&c, &b); // f^{-A3*(p+1)}
    let e = fp12_mul(&d, &b); // f^{-A3*(p+2)}
    let f_p1 = fp12_frobenius_p(f); // f^p
    let g = fp12_mul(f, &f_p1); // f^{p+1}
    let h = fp12_cyclotomic_pow(&g, SM9_NINE); // f^{9(p+1)}
    let i = fp12_mul(&e, &h); // f^{-A3*(p+2)+9(p+1)}
    let j = fp12_square(f); // f^2
    let k = fp12_square(&j); // f^4
    let l = fp12_mul(&k, &i); // f^{4 + -A3*(p+2) + 9(p+1)}
    let m = fp12_square(&f_p1); // f^{2p}
    let n = fp12_mul(&d, &m); // f^{-A3*(p+1)+2p}
    let o = fp12_frobenius_p2(f); // f^{p^2}
    let p_var = fp12_mul(&o, &n); // f^{p^2-A3*(p+1)+2p}
    let q = fp12_cyclotomic_pow(&p_var, SM9_A2); // ...^{A2}
    let r = fp12_mul(&q, &l);
    let s = fp12_frobenius_p3(f); // f^{p^3}
    fp12_mul(&s, &r)
}

/// 最终幂指数：f^{(p^12-1)/r}
pub fn final_exp(f: &Fp12) -> Fp12 {
    let f_easy = final_exp_easy(f);
    final_exp_hard(&f_easy)
}

// ── 配对函数 ────────────────────────────────────────────────────────────────

/// SM9 R-ate 配对 e(P, Q)：G1 × G2 → GT
///
/// # 参数
/// - `p`: G1 上的点（Fp）
/// - `q`: G2 上的点（Fp2）
///
/// # 返回
/// GT = Fp12 中的配对结果
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
    let f = miller_loop(q, p);
    final_exp(&f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9::groups::g1::G1Affine;
    use crate::sm9::groups::g2::G2Affine;

    #[test]
    fn test_pairing_no_panic() {
        // 测试配对计算不 panic（完整验证需与参考实现对比）
        let p = G1Affine::generator();
        let q = G2Affine::generator();
        let _gt = pairing(&p, &q);
    }
}
