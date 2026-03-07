//! SM4 核心加解密与密钥展开（GB/T 32907-2016 §6）
//!
//! # 安全说明
//!
//! S-box 使用**纯布尔电路位切片**实现（路径 A），完全消除内存访问，
//! 仅使用 AND/XOR/OR/NOT 位运算，无缓存时序侧信道攻击面。

use zeroize::{Zeroize, ZeroizeOnDrop};

// ── 常量 ──────────────────────────────────────────────────────────────────────

/// 系统参数 FK（GB/T 32907 §A.1）
const FK: [u32; 4] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

/// 常数密钥 CK（GB/T 32907 §A.1）
#[rustfmt::skip]
const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

// ── 纯布尔电路 S-box（路径 A：零内存访问位切片实现）─────────────────────────
//
// 仅使用 AND/XOR/OR/NOT 位运算，完全消除内存查表，无缓存时序侧信道。
//
// 算法来源：emmansun/sm4bs（sbox64 函数）经标量化提取并验证（256/256 全表正确）。
// 结构：输入线性层 -> GF(2^4) 求逆（top+middle 函数）-> 输出线性层（bottom+output 函数）
//
// Reason: 纯布尔电路（路径 A）完全消除内存访问，不依赖缓存行为，
//   在所有微架构上均无侧信道风险。

/// SM4 S-box 布尔电路实现（路径 A）
///
/// 仅使用 `&`/`^`/`|`/`!` 位运算，零内存访问，无条件分支。
/// 每个中间变量为 0 或 1（对应输入字节的各个位平面）。
#[allow(dead_code)]
#[inline]
pub(crate) fn sbox_ct(x: u8) -> u8 {
    // 提取输入字节的 8 个位（b0 = LSB, b7 = MSB）
    let b0 = x & 1;
    let b1 = (x >> 1) & 1;
    let b2 = (x >> 2) & 1;
    let b3 = (x >> 3) & 1;
    let b4 = (x >> 4) & 1;
    let b5 = (x >> 5) & 1;
    let b6 = (x >> 6) & 1;
    let b7 = (x >> 7) & 1;

    // ── 输入线性层（input function）──────────────────────────────────────────
    // Reason: 将输入 8 位映射为中间变量 g0..g7, m0..m9，为 GF(2^4) 求逆做准备。
    let t1 = b7 ^ b5;
    let t2 = 1 ^ (b5 ^ b1); // NOT(b5 ^ b1) = g4
    let g5 = 1 ^ b0; // NOT(b0)
    let t3 = 1 ^ (b0 ^ t2); // NOT(b0 ^ t2) = m1
    let t4 = b6 ^ b2; // m4
    let t5 = b3 ^ t3; // g3
    let t6 = b4 ^ t1; // m0
    let t7 = b1 ^ t5; // g1
    let t8 = b1 ^ t4; // m2
    let t9 = t6 ^ t8; // m8
    let t10 = t6 ^ t7; // g0
    let t11 = 1 ^ (b3 ^ t1); // NOT(b3 ^ t1) = m5
    let t12 = 1 ^ (b6 ^ t9); // NOT(b6 ^ t9) = m9

    let g0 = t10;
    let g1 = t7;
    let g2 = t4 ^ t10;
    let g3 = t5;
    let g4 = t2;
    let g6 = t11 ^ t2;
    let g7 = t12 ^ (t11 ^ t2);
    let m0 = t6;
    let m1 = t3;
    let m2 = t8;
    let m3 = t3 ^ t12;
    let m4 = t4;
    let m5 = t11;
    let m6 = b1;
    let m7 = t11 ^ m3;
    let m8 = t9;
    let m9 = t12;

    // ── Top 函数（GF(2^4) 求逆的输入准备）────────────────────────────────────
    // Reason: 将 16 个中间变量组合为 p0..p3，供 GF(2^2) 中间层使用。
    let t2t = m0 & m1;
    let t3t = g0 & g4;
    let t4t = g3 & g7;
    let t7t = g3 | g7;
    let t11t = m4 & m5;
    let t10t = m3 & m2;
    let t12t = m3 | m2;
    let t6t = g6 | g2;
    let t9t = m6 | m7;
    let t5t = m8 & m9;
    let t8t = m8 | m9;
    let t14t = t3t ^ t2t;
    let t16t = t5t ^ t14t;
    let t20t = t16t ^ t7t;
    let t17t = t9t ^ t10t;
    let t18t = t11t ^ t12t;
    let p2 = t20t ^ t18t;
    let p0 = t6t ^ t16t;
    let t1t = g5 & g1;
    let t13t = t1t ^ t2t;
    let t15t = t13t ^ t4t;
    let p3 = (t6t ^ t15t) ^ t17t;
    let p1 = t8t ^ t15t;

    // ── Middle 函数（GF(2^2) 求逆）───────────────────────────────────────────
    // Reason: 在 GF(2^2) 上对 (p0,p1,p2,p3) 组成的元素进行求逆，输出 l0..l3。
    let t0m = p1 & p2;
    let t1m = p3 & p0;
    let t2m = p0 & p2;
    let t3m = p1 & p3;
    let t4m = t0m & t2m;
    let t5m = t1m ^ t3m;
    let t6m = t5m | p0;
    let t7m = t2m | p3;
    let l3 = t4m ^ t6m;
    let t9m = t7m ^ t3m;
    let l0 = t0m ^ t9m;
    let t11m = p2 | t5m;
    let l1 = t11m ^ t1m;
    let t12m = p1 | t2m;
    let l2 = t12m ^ t5m;

    // ── Bottom 函数（GF(2^4) 求逆的输出组合）─────────────────────────────────
    // Reason: 将 l0..l3 与输入中间变量结合，得到 r0..r11（12 个中间结果）。
    let k4 = l2 ^ l3;
    let k3 = l1 ^ l3;
    let k2 = l0 ^ l2;
    let k0 = l0 ^ l1;
    let k1 = k2 ^ k3;

    let e0 = m1 & k0;
    let e1 = g5 & l1;
    let r0 = e0 ^ e1;
    let e2 = g4 & l0;
    let r1 = e2 ^ e1;
    let e3 = m7 & k3;
    let e4 = m5 & k2;
    let r2 = e3 ^ e4;
    let e5 = m3 & k1;
    let r3 = e5 ^ e4;
    let e6 = m9 & k4;
    let e7 = g7 & l3;
    let r4 = e6 ^ e7;
    let e8 = g6 & l2;
    let r5 = e8 ^ e7;
    let e9 = m0 & k0;
    let e10 = g1 & l1;
    let r6 = e9 ^ e10;
    let e11 = g0 & l0;
    let r7 = e11 ^ e10;
    let e12 = m6 & k3;
    let e13 = m4 & k2;
    let r8 = e12 ^ e13;
    let e14 = m2 & k1;
    let r9 = e14 ^ e13;
    let e15 = m8 & k4;
    let e16 = g3 & l3;
    let r10 = e15 ^ e16;
    let e17 = g2 & l2;
    let r11 = e17 ^ e16;

    // ── 输出线性层（output function）──────────────────────────────────────────
    // Reason: 将 r0..r11 组合为输出字节的 8 个位。
    let t1o = r7 ^ r9;
    let t2o = r1 ^ t1o;
    let t3o = r3 ^ t2o;
    let t4o = r5 ^ r3;
    let t5o = r4 ^ t4o;
    let t6o = r0 ^ r4;
    let t7o = r11 ^ r7;

    let b5o = t1o ^ t4o;
    let b2o = t1o ^ t6o;
    let t10o = r2 ^ t5o;
    let b3o = r10 ^ r8;
    let b1o = 1 ^ (t3o ^ b3o);
    let b6o = t10o ^ b1o;
    let b4o = 1 ^ (t3o ^ t7o);
    let b0o = t6o ^ b4o;
    let b7o = 1 ^ (r10 ^ r6);

    // 将 8 个输出位重组为字节
    b0o | (b1o << 1) | (b2o << 2) | (b3o << 3) | (b4o << 4) | (b5o << 5) | (b6o << 6) | (b7o << 7)
}

/// SM4 τ 变换：4 字节 u32 一次性位切片 S-box（常量时间，4-way 并行）
///
/// # 实现原理
///
/// 将 4 字节同一位位置的 4 个 bit 打包到一个 u32 的低 4 位，
/// 单次执行布尔电路（同 `sbox_ct`），等效并行处理所有 4 个字节。
///
/// 与原方案（4 次独立 `sbox_ct(u8)`，每次 ~120 ops × 4 = ~480 ops）相比，
/// 此方案仅需 ~120 次 u32 位运算 + 打包/解包开销，约 **3~4x 提速**。
///
/// # 安全性
///
/// 继承 `sbox_ct` 的全部安全属性：零内存访问、无条件分支。
/// u32 各位位置相互独立，常量 `0xF`（低 4 位全 1）用于取反。
#[inline]
fn tau(a: u32) -> u32 {
    let bytes = a.to_be_bytes();

    // ── 打包：bits[i] 低 4 位 = [byte0, byte1, byte2, byte3] 的第 i 位 ──
    // Reason: 打包后每个 u32 变量的 bit-j 对应第 j 个字节的该位面，
    //   XOR/AND/OR 在 4 个独立"通道"上并行执行，语义不变。
    let mut bits = [0u32; 8];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = ((bytes[0] >> i) & 1) as u32
            | (((bytes[1] >> i) & 1) as u32) << 1
            | (((bytes[2] >> i) & 1) as u32) << 2
            | (((bytes[3] >> i) & 1) as u32) << 3;
    }
    let [b0, b1, b2, b3, b4, b5, b6, b7] = bits;

    // ── S-box 布尔电路（与 sbox_ct 完全相同，1 → 0xF）────────────────────
    // Reason: sbox_ct 用 `1 ^ x` 表示 NOT；此处 4 通道并行故改为 `0xF ^ x`，
    //   使 4 个 bit 位置都被正确取反，其余位运算（^/&/|）无需修改。
    let t1 = b7 ^ b5;
    let t2 = 0xF ^ (b5 ^ b1);
    let g5 = 0xF ^ b0;
    let t3 = 0xF ^ (b0 ^ t2);
    let t4 = b6 ^ b2;
    let t5 = b3 ^ t3;
    let t6 = b4 ^ t1;
    let t7 = b1 ^ t5;
    let t8 = b1 ^ t4;
    let t9 = t6 ^ t8;
    let t10 = t6 ^ t7;
    let t11 = 0xF ^ (b3 ^ t1);
    let t12 = 0xF ^ (b6 ^ t9);

    let g0 = t10;
    let g1 = t7;
    let g2 = t4 ^ t10;
    let g3 = t5;
    let g4 = t2;
    let g6 = t11 ^ t2;
    let g7 = t12 ^ (t11 ^ t2);
    let m0 = t6;
    let m1 = t3;
    let m2 = t8;
    let m3 = t3 ^ t12;
    let m4 = t4;
    let m5 = t11;
    let m6 = b1;
    let m7 = t11 ^ m3;
    let m8 = t9;
    let m9 = t12;

    let t2t = m0 & m1;
    let t3t = g0 & g4;
    let t4t = g3 & g7;
    let t7t = g3 | g7;
    let t11t = m4 & m5;
    let t10t = m3 & m2;
    let t12t = m3 | m2;
    let t6t = g6 | g2;
    let t9t = m6 | m7;
    let t5t = m8 & m9;
    let t8t = m8 | m9;
    let t14t = t3t ^ t2t;
    let t16t = t5t ^ t14t;
    let t20t = t16t ^ t7t;
    let t17t = t9t ^ t10t;
    let t18t = t11t ^ t12t;
    let p2 = t20t ^ t18t;
    let p0 = t6t ^ t16t;
    let t1t = g5 & g1;
    let t13t = t1t ^ t2t;
    let t15t = t13t ^ t4t;
    let p3 = (t6t ^ t15t) ^ t17t;
    let p1 = t8t ^ t15t;

    let t0m = p1 & p2;
    let t1m = p3 & p0;
    let t2m = p0 & p2;
    let t3m = p1 & p3;
    let t4m = t0m & t2m;
    let t5m = t1m ^ t3m;
    let t6m = t5m | p0;
    let t7m = t2m | p3;
    let l3 = t4m ^ t6m;
    let t9m = t7m ^ t3m;
    let l0 = t0m ^ t9m;
    let t11m = p2 | t5m;
    let l1 = t11m ^ t1m;
    let t12m = p1 | t2m;
    let l2 = t12m ^ t5m;

    let k4 = l2 ^ l3;
    let k3 = l1 ^ l3;
    let k2 = l0 ^ l2;
    let k0 = l0 ^ l1;
    let k1 = k2 ^ k3;

    let e0 = m1 & k0;
    let e1 = g5 & l1;
    let r0 = e0 ^ e1;
    let e2 = g4 & l0;
    let r1 = e2 ^ e1;
    let e3 = m7 & k3;
    let e4 = m5 & k2;
    let r2 = e3 ^ e4;
    let e5 = m3 & k1;
    let r3 = e5 ^ e4;
    let e6 = m9 & k4;
    let e7 = g7 & l3;
    let r4 = e6 ^ e7;
    let e8 = g6 & l2;
    let r5 = e8 ^ e7;
    let e9 = m0 & k0;
    let e10 = g1 & l1;
    let r6 = e9 ^ e10;
    let e11 = g0 & l0;
    let r7 = e11 ^ e10;
    let e12 = m6 & k3;
    let e13 = m4 & k2;
    let r8 = e12 ^ e13;
    let e14 = m2 & k1;
    let r9 = e14 ^ e13;
    let e15 = m8 & k4;
    let e16 = g3 & l3;
    let r10 = e15 ^ e16;
    let e17 = g2 & l2;
    let r11 = e17 ^ e16;

    let t1o = r7 ^ r9;
    let t2o = r1 ^ t1o;
    let t3o = r3 ^ t2o;
    let t4o = r5 ^ r3;
    let t5o = r4 ^ t4o;
    let t6o = r0 ^ r4;
    let t7o = r11 ^ r7;
    let b5o = t1o ^ t4o;
    let b2o = t1o ^ t6o;
    let t10o = r2 ^ t5o;
    let b3o = r10 ^ r8;
    let b1o = 0xF ^ (t3o ^ b3o);
    let b6o = t10o ^ b1o;
    let b4o = 0xF ^ (t3o ^ t7o);
    let b0o = t6o ^ b4o;
    let b7o = 0xF ^ (r10 ^ r6);

    // ── 解包：8 个 u32 低 4 位 → 4 个输出字节 ──────────────────────────────
    let ob = [b0o, b1o, b2o, b3o, b4o, b5o, b6o, b7o];
    let mut out = [0u8; 4];
    for (i, &v) in ob.iter().enumerate() {
        out[0] |= ((v & 1) as u8) << i;
        out[1] |= (((v >> 1) & 1) as u8) << i;
        out[2] |= (((v >> 2) & 1) as u8) << i;
        out[3] |= (((v >> 3) & 1) as u8) << i;
    }
    u32::from_be_bytes(out)
}

/// SM4 加密轮函数 T（GB/T 32907 §6.2.1）
#[inline]
fn t_enc(a: u32) -> u32 {
    let b = tau(a);
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// SM4 密钥扩展轮函数 T'（GB/T 32907 §6.2.2）
#[inline]
fn t_key(a: u32) -> u32 {
    let b = tau(a);
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

// ── Sm4Key ────────────────────────────────────────────────────────────────────

/// SM4 密钥（含预展开的 32 个轮密钥）
///
/// 构造时自动完成密钥展开，后续加解密操作直接使用缓存的轮密钥，
/// 避免每次调用重复展开的开销（~30% 吞吐提升）。
///
/// Drop 时自动清零所有轮密钥材料。
///
/// # 示例
///
/// ```rust
/// use libsmx::sm4::Sm4Key;
///
/// let key = [0u8; 16];
/// let sm4 = Sm4Key::new(&key);
/// let mut block = [0u8; 16];
/// sm4.encrypt_block(&mut block);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sm4Key {
    /// 32 个轮密钥（加密顺序）
    rk: [u32; 32],
}

impl Sm4Key {
    /// 从 16 字节密钥构造 `Sm4Key`，自动展开轮密钥
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u32; 32];
        expand_key(key, &mut rk);
        Self { rk }
    }

    /// 加密单个 16 字节块（原地操作）
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut x = load_block(block);
        encrypt_rounds(&mut x, &self.rk);
        store_block(block, &x);
    }

    /// 解密单个 16 字节块（原地操作，轮密钥逆序使用）
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut x = load_block(block);
        decrypt_rounds(&mut x, &self.rk);
        store_block(block, &x);
    }

    /// 获取轮密钥引用（仅供 modes 子模块使用）
    pub(crate) fn round_keys(&self) -> &[u32; 32] {
        &self.rk
    }
}

// ── 内部辅助 ──────────────────────────────────────────────────────────────────

/// SM4 密钥展开（GB/T 32907 §6.2.2）
fn expand_key(key: &[u8; 16], rk: &mut [u32; 32]) {
    let mk = [
        u32::from_be_bytes(key[0..4].try_into().unwrap()),
        u32::from_be_bytes(key[4..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..12].try_into().unwrap()),
        u32::from_be_bytes(key[12..16].try_into().unwrap()),
    ];
    let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

    for i in 0..32 {
        let tmp = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
        rk[i] = k[i % 4] ^ t_key(tmp);
        k[i % 4] = rk[i];
    }
}

/// 将 16 字节块加载为 4 个 u32（大端）
#[inline]
fn load_block(b: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u32::from_be_bytes(b[4..8].try_into().unwrap()),
        u32::from_be_bytes(b[8..12].try_into().unwrap()),
        u32::from_be_bytes(b[12..16].try_into().unwrap()),
    ]
}

/// 将 4 个 u32 存储为 16 字节块（大端）
#[inline]
fn store_block(b: &mut [u8; 16], x: &[u32; 4]) {
    b[0..4].copy_from_slice(&x[0].to_be_bytes());
    b[4..8].copy_from_slice(&x[1].to_be_bytes());
    b[8..12].copy_from_slice(&x[2].to_be_bytes());
    b[12..16].copy_from_slice(&x[3].to_be_bytes());
}

/// SM4 加密轮变换（32 轮，轮密钥正序）
fn encrypt_rounds(x: &mut [u32; 4], rk: &[u32; 32]) {
    for &rk_i in rk.iter() {
        let tmp = x[1] ^ x[2] ^ x[3] ^ rk_i;
        let next = x[0] ^ t_enc(tmp);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = next;
    }
    x.reverse(); // GB/T 32907 §6.2.1：输出为 (X35, X34, X33, X32)
}

/// SM4 解密轮变换（32 轮，轮密钥逆序）
fn decrypt_rounds(x: &mut [u32; 4], rk: &[u32; 32]) {
    for i in (0..32).rev() {
        let tmp = x[1] ^ x[2] ^ x[3] ^ rk[i];
        let next = x[0] ^ t_enc(tmp);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = next;
    }
    x.reverse();
}

/// 辅助：加密独立块（不缓存轮密钥，供 modes 一次性使用）
pub(crate) fn encrypt_block_raw(rk: &[u32; 32], block: &[u8; 16]) -> [u8; 16] {
    let mut x = load_block(block);
    encrypt_rounds(&mut x, rk);
    let mut out = [0u8; 16];
    store_block(&mut out, &x);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32907-2016 附录 A：单块加密测试向量
    #[test]
    fn test_encrypt_vector() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let mut block = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let expected = [
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
            0x42, 0x46,
        ];

        let sm4 = Sm4Key::new(&key);
        sm4.encrypt_block(&mut block);
        assert_eq!(block, expected, "SM4 加密测试向量不匹配");
    }

    /// GB/T 32907-2016 附录 A：单块解密（加密的逆操作）
    #[test]
    fn test_decrypt_roundtrip() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plain = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];

        let sm4 = Sm4Key::new(&key);
        let mut block = plain;
        sm4.encrypt_block(&mut block);
        sm4.decrypt_block(&mut block);
        assert_eq!(block, plain, "SM4 加解密往返不一致");
    }

    /// 布尔电路 S-box 与标准 S-box 表一致性验证（256 点全表）
    #[test]
    fn test_sbox_ct_correct() {
        #[rustfmt::skip]
        const REF: [u8; 256] = [
            0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
            0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
            0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
            0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
            0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
            0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
            0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
            0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
            0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
            0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
            0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
            0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
            0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
            0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
            0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
            0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
        ];
        for i in 0u8..=255 {
            assert_eq!(
                sbox_ct(i),
                REF[i as usize],
                "S-box 布尔电路实现在输入 {i:#04x} 处与标准不一致"
            );
        }
    }
}
