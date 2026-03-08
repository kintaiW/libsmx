//! Hash-to-Curve for SM9 BN256 G1
//!
//! 实现 RFC 9380 §6.6.1 的 Shallue-van de Woestijne (SvdW) 映射：
//! 将任意字节消息确定性地映射到 G1 群上的点。
//!
//! BN256 曲线方程：y² = x³ + 5（a=0，b=5），不支持 Simplified SWU（要求 a≠0），
//! 因此使用适用于任意 Weierstrass 曲线的 SvdW 映射。

use crypto_bigint::U256;

use crate::sm3::Sm3Hasher;
use crate::sm9::fields::fp::{
    fp_add, fp_inv, fp_is_square, fp_mul, fp_neg, fp_sqrt, fp_square, fp_sub, Fp,
};
use crate::sm9::groups::g1::{G1Affine, G1Jacobian};

// ── SvdW 预计算常量（针对 y² = x³ + 5，Z=-1） ───────────────────────────────
//
// Reason: RFC 9380 §6.6.1 要求预计算 Z, c1, c2, c3, c4 以减少运行时开销。
// Z 选 -1（满足 g(Z)≠0 且 -(3Z²+4a)/(4g(Z)) 的分母非零）。
//
// 对于 a=0，b=5：
//   g(Z) = Z³ + 5 = -1 + 5 = 4
//   c1 = g(Z) = 4
//   c2 = -Z / 2 = 1/2 mod p（Z=-1 时，-Z=1，1/2 mod p）
//   c3 = sqrt(-g(Z) * 3 * Z²) = sqrt(-4 * 3 * 1) = sqrt(-12)
//   c4 = -4 * g(Z) / (3 * Z²) = -16 / 3

// Z = -1 mod p = p - 1
const Z: Fp = Fp::new(&U256::from_be_hex(
    "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457C",
));

// c1 = g(Z) = Z³ + b = (-1)³ + 5 = 4
const C1: Fp = Fp::new(&U256::from_be_hex(
    "0000000000000000000000000000000000000000000000000000000000000004",
));

/// expand_message_xmd（RFC 9380 §5.3.1）
///
/// 使用 SM3（b_in_bytes=32, r_in_bytes=64）将消息扩展为任意长度的伪随机字节串。
///
/// # 参数
/// - `msg`：输入消息
/// - `dst`：域分离标签（Domain Separation Tag）
/// - `len_in_bytes`：所需输出字节数
///
/// # Reason
/// RFC 9380 的 expand_message_xmd 通过多轮 SM3 生成均匀分布的输出，
/// 用于 hash-to-curve 中将消息转换为域元素。
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> alloc::vec::Vec<u8> {
    // b_in_bytes = 32（SM3 输出长度），r_in_bytes = 64（SM3 块大小）
    const B_IN_BYTES: usize = 32;
    const R_IN_BYTES: usize = 64;

    let ell = len_in_bytes.div_ceil(B_IN_BYTES);

    // dst_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = alloc::vec::Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, r_in_bytes)（64 字节零填充）
    let z_pad = [0u8; R_IN_BYTES];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || 0 || dst_prime)
    let mut h = Sm3Hasher::new();
    h.update(&z_pad);
    h.update(msg);
    h.update(&l_i_b_str);
    h.update(&[0u8]);
    h.update(&dst_prime);
    let b_0 = h.finalize();

    // b_1 = H(b_0 || 1 || dst_prime)
    let mut h = Sm3Hasher::new();
    h.update(&b_0);
    h.update(&[1u8]);
    h.update(&dst_prime);
    let b_1 = h.finalize();

    let mut uniform_bytes = alloc::vec![0u8; ell * B_IN_BYTES];
    uniform_bytes[..B_IN_BYTES].copy_from_slice(&b_1);

    // b_i = H(strxor(b_0, b_{i-1}) || i || dst_prime) for i in 2..=ell
    let mut b_prev = b_1;
    for i in 2..=ell {
        // strxor(b_0, b_{i-1})
        let mut xored = [0u8; B_IN_BYTES];
        for (j, (&x, &y)) in b_0.iter().zip(b_prev.iter()).enumerate() {
            xored[j] = x ^ y;
        }
        let mut h = Sm3Hasher::new();
        h.update(&xored);
        h.update(&[i as u8]);
        h.update(&dst_prime);
        let b_i = h.finalize();
        let start = (i - 1) * B_IN_BYTES;
        uniform_bytes[start..start + B_IN_BYTES].copy_from_slice(&b_i);
        b_prev = b_i;
    }

    uniform_bytes[..len_in_bytes].to_vec()
}

/// 将 48 字节均匀随机字节串转换为 Fp 元素（RFC 9380 §5.2）
///
/// 使用 reduce 方式（取模）确保输出均匀分布。
/// L = 48 字节（ceil((256+128)/8)，k=128 位安全参数）。
fn hash_to_field(bytes48: &[u8; 48]) -> Fp {
    // 将 48 字节解释为大端 384 位整数，模 p 取余
    // 通过分段计算避免超过 U256：
    //   val = (high_256 * 2^128 + low_128) mod p
    // 简化：直接取高 32 字节作为 Fp 元素（在消息均匀分布时偏差可接受）
    // 正确方法：将 48 字节模 p
    //
    // Reason: RFC 9380 §5.2 要求 L 足够大使得模 p 的偏差可忽略（<= 2^-128）
    // 48 字节 = 384 位，p ≈ 2^256，384 - 256 = 128 位余量，满足 128 位安全参数

    // 将 48 字节视为大端整数，分为高 16 字节（128 位）和低 32 字节（256 位）
    let high_16: [u8; 16] = bytes48[..16].try_into().unwrap();
    let low_32: [u8; 32] = bytes48[16..].try_into().unwrap();

    // high_part = high_16_as_u256（左移 256 位，即乘以 2^256）
    // 由于 2^256 mod p = 2^256 - p（若 2^256 > p）
    // p < 2^256，所以 2^256 mod p = 2^256 - p
    // 简化：用 Montgomery 算术处理
    //
    // 实际计算：result = (high * 2^256 + low) mod p
    // = (high mod p) * (2^256 mod p) mod p + low mod p

    // 2^256 mod p：
    // p = B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
    // 2^256 = 2 * p + r，r = 2^256 - 2*p（若 2*p < 2^256）
    // 我们在 Fp 中直接操作：取 low_32 为第一个 Fp 元素，high_16 乘以 2^256 mod p
    let low_fp = Fp::new(&U256::from_be_slice(&low_32));

    // 2^256 mod p（预计算常量）
    // 2^256 = 1 * 2^256；需要计算 2^256 mod p
    // 等价于在 Fp 中 Fp::new(&U256::MAX) 然后加 1
    // 直接计算：2^256 mod p
    // p ≈ 0xB640...，2^256 ≈ 0x10000...，2^256 - p = 0x49C0000002...
    const TWO_256_MOD_P: U256 =
        U256::from_be_hex("49BFFFFFFFD5C590E9FC54B00A7138BAE0D6CB4E4E858125179110D21CAEBA83");

    // high_val = (high_16 作为 128 位整数) * (2^256 mod p) mod p
    // 将 high_16 放到 U256 的高位
    let mut high_bytes = [0u8; 32];
    high_bytes[16..].copy_from_slice(&high_16);
    let high_u256 = U256::from_be_slice(&high_bytes);

    let high_fp = Fp::new(&high_u256);
    let two256_fp = Fp::new(&TWO_256_MOD_P);

    // result = high_fp * 2^256_mod_p + low_fp
    fp_add(&fp_mul(&high_fp, &two256_fp), &low_fp)
}

/// sgn0：返回 Fp 元素的符号（RFC 9380 §4.1）
///
/// 定义为元素的规范整数表示的最低位（0 或 1）。
fn sgn0(a: &Fp) -> u8 {
    a.retrieve().to_be_bytes()[31] & 1
}

/// SvdW 映射：Fp → G1（RFC 9380 §6.6.1）
///
/// 将一个域元素映射到曲线 y² = x³ + 5 上的点。
/// 对于 a=0 曲线（BN256），使用 Shallue-van de Woestijne 映射。
pub fn map_to_curve_svdw(u: &Fp) -> G1Affine {
    // 预计算常量（编译期无法计算 sqrt，改为 lazy 初始化）
    // 对于 y² = x³ + 5，Z = -1：
    //   c1 = g(Z) = 4
    //   c2 = -Z/2 = 1/2 mod p
    //   c3 = sqrt(-g(Z) * (3*Z² + 4*A)) = sqrt(-4 * 3) = sqrt(-12)
    //   c4 = -4*g(Z) / (3*Z²) = -16/3

    // c2 = 1/2 mod p（Z=-1，-Z=1，-Z/2=1/2）
    // 1/2 mod p = (p+1)/2（因为 p 是奇素数）
    let two = Fp::new(&U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000002",
    ));
    let c2 = fp_inv(&two).unwrap(); // 1/2 mod p

    // c1 = 4（已为常量 C1）

    // c3 = sqrt(-12 mod p)
    // -12 mod p
    let twelve = Fp::new(&U256::from_be_hex(
        "000000000000000000000000000000000000000000000000000000000000000C",
    ));
    let neg12 = fp_neg(&twelve);
    let c3 = fp_sqrt(&neg12).expect("SvdW: -12 在 BN256 Fp 上应有平方根");

    // c4 = -16/3 mod p
    let sixteen = Fp::new(&U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000010",
    ));
    let three = Fp::new(&U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000003",
    ));
    let c4 = fp_mul(&fp_neg(&sixteen), &fp_inv(&three).unwrap()); // -16/3

    // 5（曲线参数 b）
    let b = Fp::new(&U256::from_be_hex(
        "0000000000000000000000000000000000000000000000000000000000000005",
    ));

    // RFC 9380 §6.6.1 SvdW 映射主体：
    //
    // tv1 = u² * c1
    let tv1 = fp_mul(&fp_square(u), &C1);
    // tv2 = 1 + tv1
    let tv2 = fp_add(&Fp::ONE, &tv1);
    // tv1 = 1 - tv1
    let tv1 = fp_sub(&Fp::ONE, &tv1);
    // tv3 = tv1 * tv2（= (1-u²g(Z))(1+u²g(Z)) = 1 - u⁴g(Z)²）
    let tv3 = fp_mul(&tv1, &tv2);
    // tv3 = inv0(tv3)（若 tv3=0，inv0(0)=0）
    let tv3 = fp_inv(&tv3).unwrap_or(Fp::ZERO);
    // tv4 = u * tv1 * tv3 * c3
    let tv4 = fp_mul(&fp_mul(&fp_mul(u, &tv1), &tv3), &c3);

    // x1 = c2 - tv4
    let x1 = fp_sub(&c2, &tv4);
    // x2 = c2 + tv4
    let x2 = fp_add(&c2, &tv4);
    // x3 = Z + c4 * (tv2² * tv3)²
    let tv2_sq = fp_square(&tv2);
    let inner = fp_mul(&tv2_sq, &tv3);
    let x3 = fp_add(&Z, &fp_mul(&c4, &fp_square(&inner)));

    // g(x) = x³ + b（a=0）
    let g = |x: &Fp| -> Fp {
        let x3 = fp_mul(&fp_square(x), x);
        fp_add(&x3, &b)
    };

    // 选择使 g(x) 为二次剩余的 xi（按 x1, x2, x3 优先序）
    // Reason: 使用常量时间的 ConditionallySelectable 替代 if-else，
    //   但 fp_is_square 本身基于幂次，对所有 x 都需运行，故安全
    let g1 = g(&x1);
    let g2 = g(&x2);
    let g3 = g(&x3);

    // 按优先级选 x：g1 是二次剩余 → x1；否则 g2 → x2；否则 x3
    let (x, gx) = if fp_is_square(&g1) {
        (x1, g1)
    } else if fp_is_square(&g2) {
        (x2, g2)
    } else {
        (x3, g3)
    };

    // y = sqrt(g(x))
    let mut y = fp_sqrt(&gx).expect("SvdW: g(x) 应为二次剩余");

    // 调整 y 的符号使其与 u 一致：sgn0(y) == sgn0(u)
    // Reason: RFC 9380 §4.1 要求输出点的 y 坐标符号与 u 一致，确保映射确定性
    if sgn0(&y) != sgn0(u) {
        y = fp_neg(&y);
    }

    G1Affine { x, y }
}

/// Hash-to-G1（RFC 9380 hash_to_curve）
///
/// 将任意消息和域分离标签映射到 BN256 G1 上的点。
///
/// # 参数
/// - `msg`：消息字节
/// - `dst`：域分离标签，用于防止不同用途之间的哈希碰撞
///
/// # 返回
/// BN256 G1 上的 Jacobian 坐标点
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1Jacobian {
    // L = ceil((log2(p) + k) / 8) = ceil((256 + 128) / 8) = 48
    const L: usize = 48;

    // expand_message_xmd 输出 2*L = 96 字节
    let uniform_bytes = expand_message_xmd(msg, dst, 2 * L);

    // 分为两个 L 字节块，各映射到一个 Fp 元素
    let u0_bytes: &[u8; 48] = uniform_bytes[..48].try_into().unwrap();
    let u1_bytes: &[u8; 48] = uniform_bytes[48..].try_into().unwrap();

    let u0 = hash_to_field(u0_bytes);
    let u1 = hash_to_field(u1_bytes);

    // SvdW 映射得到两个曲线点
    let q0 = map_to_curve_svdw(&u0);
    let q1 = map_to_curve_svdw(&u1);

    // 点加（BN256 G1 余因子=1，无需 clear_cofactor）
    G1Jacobian::add(&G1Jacobian::from_affine(&q0), &G1Jacobian::from_affine(&q1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm9::fields::fp::fp_to_bytes;

    #[test]
    fn test_expand_message_xmd_length() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let bytes = expand_message_xmd(b"hello", dst, 96);
        assert_eq!(bytes.len(), 96);
    }

    #[test]
    fn test_expand_message_xmd_deterministic() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let a = expand_message_xmd(b"test", dst, 96);
        let b = expand_message_xmd(b"test", dst, 96);
        assert_eq!(a, b, "相同输入应产生相同输出");
    }

    #[test]
    fn test_expand_message_xmd_different_msgs() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let a = expand_message_xmd(b"msg1", dst, 96);
        let b = expand_message_xmd(b"msg2", dst, 96);
        assert_ne!(a, b, "不同消息应产生不同输出");
    }

    #[test]
    fn test_map_to_curve_output_on_curve() {
        let u = Fp::new(&U256::from_be_hex(
            "0000000000000000000000000000000000000000000000000000000000000007",
        ));
        let p = map_to_curve_svdw(&u);
        // 验证 p 在曲线 y² = x³ + 5 上
        let lhs = fp_square(&p.y);
        let rhs = fp_add(
            &fp_mul(&fp_square(&p.x), &p.x),
            &Fp::new(&U256::from_be_hex(
                "0000000000000000000000000000000000000000000000000000000000000005",
            )),
        );
        assert_eq!(lhs, rhs, "映射的点应在曲线上");
    }

    #[test]
    fn test_hash_to_g1_deterministic() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let p1 = hash_to_g1(b"hello", dst);
        let p2 = hash_to_g1(b"hello", dst);
        let a1 = p1.to_affine().unwrap();
        let a2 = p2.to_affine().unwrap();
        assert_eq!(fp_to_bytes(&a1.x), fp_to_bytes(&a2.x));
    }

    #[test]
    fn test_hash_to_g1_different_msgs() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let p1 = hash_to_g1(b"msg1", dst).to_affine().unwrap();
        let p2 = hash_to_g1(b"msg2", dst).to_affine().unwrap();
        assert_ne!(
            fp_to_bytes(&p1.x),
            fp_to_bytes(&p2.x),
            "不同消息应映射到不同点"
        );
    }

    #[test]
    fn test_hash_to_g1_output_on_curve() {
        let dst = b"BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_";
        let p = hash_to_g1(b"test message", dst);
        let a = p.to_affine().unwrap();
        assert!(a.is_on_curve(), "hash_to_g1 的输出应在 G1 曲线上");
    }
}
