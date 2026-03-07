//! SM3 压缩函数（GB/T 32905-2016 §5）
//!
//! 本模块实现 SM3 的核心压缩函数，处理 64 字节消息块。
//! 对外不导出，仅供 [`super`] 中的 [`Sm3Hasher`](super::Sm3Hasher) 调用。

// SM3 初始哈希值（GB/T 32905 §4.3）
pub(super) const IV: [u32; 8] = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

/// 布尔函数 FF_j（GB/T 32905 §4.4）
#[inline(always)]
fn ff(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

/// 布尔函数 GG_j（GB/T 32905 §4.4）
#[inline(always)]
fn gg(x: u32, y: u32, z: u32, j: usize) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

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

/// SM3 轮常量 T_j（GB/T 32905 §4.2）
#[inline(always)]
fn t_j(j: usize) -> u32 {
    if j < 16 {
        0x79CC4519u32.rotate_left(j as u32)
    } else {
        0x7A879D8Au32.rotate_left((j % 32) as u32)
    }
}

/// SM3 压缩函数：处理一个 64 字节消息块，更新 state（GB/T 32905 §5.3.2）
pub(super) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // 消息扩展：将 64 字节分解为 16 个 u32（大端），再扩展到 W[0..67] 和 W'[0..63]
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..68 {
        let v = w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15);
        w[i] = p1(v) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
    }
    // W' 数组（W'_j = W_j XOR W_{j+4}），内联避免分配
    // w1[j] = w[j] ^ w[j+4]，在循环中直接计算

    // 压缩：64 轮
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for j in 0..64 {
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t_j(j))
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let w_j = w[j];
        let w_j4 = w[j + 4];
        let tt1 = ff(a, b, c, j)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w_j ^ w_j4);
        let tt2 = gg(e, f, g, j)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w_j);
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
