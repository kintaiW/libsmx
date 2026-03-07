//! SM3 压缩函数（GB/T 32905-2016 §5）
//!
//! 本模块实现 SM3 的核心压缩函数，处理 64 字节消息块。
//! 对外不导出，仅供 [`super`] 中的 [`Sm3Hasher`](super::Sm3Hasher) 调用。

// SM3 初始哈希值（GB/T 32905 §4.3）
pub(super) const IV: [u32; 8] = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

/// 轮常量 T_j 预计算表（GB/T 32905 §4.2）
///
/// Reason: 消除 t_j() 中的 `if j < 16` 运行时分支，
///   常量折叠后编译器直接嵌入立即数，无运行时旋转开销。
const T: [u32; 64] = {
    let mut t = [0u32; 64];
    let mut j = 0usize;
    while j < 16 {
        t[j] = 0x79CC4519u32.rotate_left(j as u32);
        j += 1;
    }
    while j < 64 {
        t[j] = 0x7A879D8Au32.rotate_left((j % 32) as u32);
        j += 1;
    }
    t
};

/// 置换函数 P0（GB/T 32905 §4.5）
#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// 置换函数 P1（GB/T 32905 §4.5）
#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// SM3 压缩函数：处理一个 64 字节消息块，更新 state（GB/T 32905 §5.3.2）
///
/// 实现说明：
/// - 轮函数分两段（j=0..15 和 j=16..63），消除 ff/gg 中的 `if j < 16` 运行时分支
/// - T_j 常量使用预计算表，消除旋转运算
/// - W' 数组内联为 w[j] ^ w[j+4]，避免额外分配
pub(super) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // ── 消息扩展 ─────────────────────────────────────────────────────────────
    // W[0..15]: 直接从块加载（大端）
    // W[16..67]: 用 P1 展开
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..68 {
        let v = w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15);
        w[i] = p1(v) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
    }

    // ── 压缩：64 轮 ──────────────────────────────────────────────────────────
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // Reason: 将 64 轮分两段展开，消除 ff/gg/T 中的 if 分支。
    // j = 0..15：FF = x^y^z，GG = x^y^z
    for j in 0..16 {
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(T[j])
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = (a ^ b ^ c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = (e ^ f ^ g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    // j = 16..63：FF = majority(x,y,z)，GG = choice(x,y,z)
    for j in 16..64 {
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(T[j])
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = ((a & b) | (a & c) | (b & c))
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = ((e & f) | (!e & g))
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}
