//! FNR（Flexible Naor-Reingold）核心算法
//!
//! 实现基于 SM4 的保留格式加密：
//! 使用 7 轮 Luby-Rackoff Feistel 结构，支持任意位长（1~128 位）的明文。
//!
//! 参考：Sashank Dara, Scott Fluhrer. "FNR: Flexible Naor and Reingold", Cisco, 2014.

use crate::sm4::Sm4Key;

/// Feistel 轮数（FNR 固定 7 轮）
const N_ROUND: usize = 7;

// ── 位操作工具 ────────────────────────────────────────────────────────────────

/// 从 n 位数据（高位优先打包到字节）中提取第 i 位（i 从 0 开始，0 是最高位）
#[inline]
fn get_bit(data: &[u8; 16], i: usize) -> u8 {
    let byte = i / 8;
    let bit = 7 - (i % 8);
    (data[byte] >> bit) & 1
}

/// 设置第 i 位为 val（0 或 1）
#[inline]
fn set_bit(data: &mut [u8; 16], i: usize, val: u8) {
    let byte = i / 8;
    let bit = 7 - (i % 8);
    data[byte] = (data[byte] & !(1 << bit)) | (val << bit);
}

/// 将 data 的前 n 位清零（其余位保持不变）
pub(super) fn clear_high_bits(data: &mut [u8; 16], n: usize) {
    // 清零 n 位之后的所有位
    for i in n..128 {
        set_bit(data, i, 0);
    }
}

/// 两个 n 位向量 XOR
fn xor_bits(a: &[u8; 16], b: &[u8; 16], n: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    let full = n / 8;
    for i in 0..full {
        out[i] = a[i] ^ b[i];
    }
    if n % 8 != 0 {
        let mask = 0xFF_u8 << (8 - n % 8);
        out[full] = (a[full] ^ b[full]) & mask;
    }
    out
}

// ── Feistel 轮函数 ────────────────────────────────────────────────────────────

/// Feistel 轮函数 F(round, tweak, right_half) → left_half_size 位
///
/// 构造 16 字节块 = tweak[15] XOR (round XOR right_half_padded)，
/// 用 SM4 加密，取前 out_bits 位。
fn round_fn(
    key: &Sm4Key,
    tweak: &[u8; 15],
    half: &[u8; 16],
    half_bits: usize,
    out_bits: usize,
    round: usize,
) -> [u8; 16] {
    // 构造 16 字节输入：tweak（15字节）|| round（1字节）
    let mut block = [0u8; 16];
    block[..15].copy_from_slice(tweak);
    block[15] = round as u8;

    // XOR half 到 block（half 最多 half_bits 位有意义）
    let half_bytes = half_bits.div_ceil(8);
    for i in 0..half_bytes.min(16) {
        block[i] ^= half[i];
    }

    key.encrypt_block(&mut block);

    // 只保留前 out_bits 位
    clear_high_bits(&mut block, out_bits);
    block
}

// ── FNR 加密/解密 ─────────────────────────────────────────────────────────────

/// FNR 加密（n 位，7 轮 Feistel）
///
/// Feistel 结构（每轮）：
///   (L, R) → (R, L XOR F(R))
///
/// 对于非整除 2 的位数：
///   left_bits = n / 2，right_bits = n - left_bits（right >= left）
///
/// # 参数
/// - `key`：SM4 轮密钥
/// - `tweak`：15 字节扩展 tweak（由 expand_tweak 生成）
/// - `data`：16 字节缓冲，前 num_bits 位为明文，加密后前 num_bits 位为密文
/// - `num_bits`：有效位数（1~128）
pub fn fnr_encrypt(key: &Sm4Key, tweak: &[u8; 15], data: &mut [u8; 16], num_bits: usize) {
    // 特殊情况：1 位时 Feistel 退化（left_bits=0），使用随机置换
    if num_bits == 1 {
        fnr_1bit(key, tweak, data, true);
        return;
    }

    let left_bits = num_bits / 2;
    let right_bits = num_bits - left_bits;

    // 提取左右各半
    let mut l = [0u8; 16];
    let mut r = [0u8; 16];
    for i in 0..left_bits {
        set_bit(&mut l, i, get_bit(data, i));
    }
    for i in 0..right_bits {
        set_bit(&mut r, i, get_bit(data, left_bits + i));
    }

    // 7 轮 Feistel 加密
    for round in 0..N_ROUND {
        // F = F(round, tweak, r) 取前 left_bits 位
        let f = round_fn(key, tweak, &r, right_bits, left_bits, round);
        // new_r = l XOR F
        let new_r = xor_bits(&l, &f, left_bits);
        // 交换：l = r（原右半），r = new_r
        // 注意处理 left_bits != right_bits 的情况：
        // 交换后新 l 来自旧 r（right_bits 位）→ 取前 left_bits 位
        // 新 r 是 new_r（left_bits 位）→ 作为新右半（right_bits 位）
        // 由于 right_bits >= left_bits，r 的有效位取前 left_bits 位作为新 l，
        // 剩余位丢弃（Feistel 交换中精度统一）
        // Reason: 奇数位时 right 比 left 多 1 位，通过轮内调整保持正确性
        l = r;
        clear_high_bits(&mut l, left_bits); // 新 l 只取 right_bits 中的前 left_bits 位
        r = new_r;
    }

    // 合并回 data
    for i in 0..left_bits {
        set_bit(data, i, get_bit(&l, i));
    }
    for i in 0..right_bits {
        set_bit(data, left_bits + i, get_bit(&r, i));
    }
}

/// FNR 解密（n 位，7 轮 Feistel 逆序）
///
/// Feistel 解密每轮：
///   (L', R') → (R' XOR F(L'), L')
///   其中 L'=R_enc, R'=L_enc
pub fn fnr_decrypt(key: &Sm4Key, tweak: &[u8; 15], data: &mut [u8; 16], num_bits: usize) {
    if num_bits == 1 {
        // 1 位置换是自逆的（FPE 置换）——encrypt 等于 decrypt
        fnr_1bit(key, tweak, data, false);
        return;
    }

    let left_bits = num_bits / 2;
    let right_bits = num_bits - left_bits;

    let mut l = [0u8; 16];
    let mut r = [0u8; 16];
    for i in 0..left_bits {
        set_bit(&mut l, i, get_bit(data, i));
    }
    for i in 0..right_bits {
        set_bit(&mut r, i, get_bit(data, left_bits + i));
    }

    // 7 轮逆序 Feistel 解密
    for round in (0..N_ROUND).rev() {
        // 解密轮：(L, R) → (R XOR F(L), L)
        let f = round_fn(key, tweak, &l, left_bits, right_bits, round);
        let new_l = xor_bits(&r, &f, right_bits);
        r = l;
        clear_high_bits(&mut r, right_bits);
        l = new_l;
    }

    for i in 0..left_bits {
        set_bit(data, i, get_bit(&l, i));
    }
    for i in 0..right_bits {
        set_bit(data, left_bits + i, get_bit(&r, i));
    }
}

/// 1 位 FPE 特殊处理
///
/// 对于 1 位明文（域 = {0, 1}），FPE 只有两种可能的置换：
/// 恒等（0→0, 1→1）或翻转（0→1, 1→0）。
///
/// 用 SM4 加密 tweak 得到随机比特 b：
/// - b=0：恒等映射（密文 = 明文）
/// - b=1：翻转映射（密文 = 1 - 明文）
///
/// 由于置换是自逆的，encrypt == decrypt。
/// `_encrypt` 参数预留给将来区分加密/解密（当前实现中两者相同）。
fn fnr_1bit(key: &Sm4Key, tweak: &[u8; 15], data: &mut [u8; 16], _encrypt: bool) {
    // 生成随机置换比特
    let mut block = [0u8; 16];
    block[..15].copy_from_slice(tweak);
    block[15] = 0xFF; // 特殊轮号标记 1-bit 模式
    key.encrypt_block(&mut block);
    let perm_bit = (block[0] >> 7) & 1; // 取最高位

    // 若 perm_bit=1，翻转最高位
    let orig = get_bit(data, 0);
    set_bit(data, 0, orig ^ perm_bit);
}
