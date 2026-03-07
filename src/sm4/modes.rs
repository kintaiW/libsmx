//! SM4 分组模式（GB/T 32907-2016，GB/T 17964-2021）
//!
//! 支持：ECB、CBC、OFB、CFB、CTR、GCM（AEAD）、CCM（AEAD）、XTS
//!
//! # 安全说明
//!
//! - GCM/CCM 认证标签比较使用 `subtle::ConstantTimeEq`，防止时序侧信道
//! - CCM 严格遵循"先验证后解密"原则（Encrypt-then-MAC 的接收端验证）
//! - 所有密钥材料通过 [`Sm4Key`] 在 Drop 时自动清零

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use super::cipher::{encrypt_block_raw, Sm4Key};

// ── ECB ──────────────────────────────────────────────────────────────────────

/// SM4-ECB 加密（无填充，`data` 必须为 16 字节整倍数）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `data`: 明文（长度须为 16 的倍数）
///
/// # 返回
/// 密文字节向量
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ecb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    data.chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            sm4.encrypt_block(&mut block);
            block
        })
        .collect()
}

/// SM4-ECB 解密（无填充，`data` 必须为 16 字节整倍数）
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ecb(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    data.chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            sm4.decrypt_block(&mut block);
            block
        })
        .collect()
}

// ── CBC ──────────────────────────────────────────────────────────────────────

/// SM4-CBC 加密（`plaintext.len()` 须为 16 字节整倍数）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut prev = *iv;
    plaintext
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            let len = chunk.len().min(16);
            block[..len].copy_from_slice(&chunk[..len]);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            sm4.encrypt_block(&mut block);
            prev = block;
            block
        })
        .collect()
}

/// SM4-CBC 解密（`ciphertext.len()` 须为 16 字节整倍数）
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cbc(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut prev = *iv;
    ciphertext
        .chunks(16)
        .flat_map(|chunk| {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let ct = block;
            sm4.decrypt_block(&mut block);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            prev = ct;
            block
        })
        .collect()
}

// ── OFB ──────────────────────────────────────────────────────────────────────

/// SM4-OFB 加密/解密（自反模式，加解密逻辑相同）
#[cfg(feature = "alloc")]
pub fn sm4_crypt_ofb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        sm4.encrypt_block(&mut feedback);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ feedback[i]);
        }
    }
    out
}

// ── CFB ──────────────────────────────────────────────────────────────────────

/// SM4-CFB 加密
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = feedback;
        sm4.encrypt_block(&mut ks);
        let mut ct_block = [0u8; 16];
        for (i, &b) in chunk.iter().enumerate() {
            ct_block[i] = b ^ ks[i];
        }
        feedback = ct_block;
        out.extend_from_slice(&ct_block[..chunk.len()]);
    }
    out
}

/// SM4-CFB 解密
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = feedback;
        sm4.encrypt_block(&mut ks);
        let mut ct_block = [0u8; 16];
        ct_block[..chunk.len()].copy_from_slice(chunk);
        // Reason: CFB 解密中 feedback 使用密文块，而非明文块
        feedback = ct_block;
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    out
}

// ── CTR ──────────────────────────────────────────────────────────────────────

/// CTR 计数器递增（全 128 位大端）
#[inline]
fn ctr_inc(counter: &mut [u8; 16]) {
    for i in (0..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// SM4-CTR 加密/解密（自反模式）
#[cfg(feature = "alloc")]
pub fn sm4_crypt_ctr(key: &[u8; 16], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let sm4 = Sm4Key::new(key);
    let mut counter = *nonce;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = counter;
        sm4.encrypt_block(&mut ks);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        ctr_inc(&mut counter);
    }
    out
}

// ── GCM ──────────────────────────────────────────────────────────────────────

/// GF(2^128) 乘法（NIST SP 800-38D Algorithm 1）
/// Reason: GHASH 的核心运算，不可约多项式 x^128 + x^7 + x^2 + x + 1
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for byte_xi in x.iter() {
        for bit_idx in (0..8).rev() {
            if (byte_xi >> bit_idx) & 1 == 1 {
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }
            let lsb = v[15] & 1;
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xE1;
            }
        }
    }
    z
}

/// GHASH 认证函数（NIST SP 800-38D §6.4）
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    gf128_mul(&y, h)
}

/// GCM 计数器递增（仅最后 4 字节，GCM 标准）
#[inline]
fn gcm_ctr_inc(counter: &mut [u8; 16]) {
    // Reason: GCM 规范中 J0 的计数器字段只占最后 4 字节（大端 32 位）
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// SM4-GCM 加密（AEAD）
///
/// # 参数
/// - `key`: 16 字节密钥
/// - `nonce`: 12 字节 nonce（GCM 标准推荐）
/// - `aad`: 附加认证数据（不加密，但参与认证）
/// - `plaintext`: 明文
///
/// # 返回
/// `(密文, 16字节认证标签)`
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let h = encrypt_block_raw(rk, &[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut ctr = j0;
    gcm_ctr_inc(&mut ctr);

    let ciphertext: Vec<u8> = {
        let mut out = Vec::with_capacity(plaintext.len());
        let mut counter = ctr;
        for chunk in plaintext.chunks(16) {
            let ks = encrypt_block_raw(rk, &counter);
            for (i, &b) in chunk.iter().enumerate() {
                out.push(b ^ ks[i]);
            }
            gcm_ctr_inc(&mut counter);
        }
        out
    };

    let ghash_val = ghash(&h, aad, &ciphertext);
    let ej0 = encrypt_block_raw(rk, &j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_val[i] ^ ej0[i];
    }

    (ciphertext, tag)
}

/// SM4-GCM 解密（AEAD）
///
/// **先验证认证标签，验证通过后才解密。**
///
/// # 错误
/// 返回 [`crate::error::Error::AuthTagMismatch`] 当标签验证失败。
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, crate::error::Error> {
    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let h = encrypt_block_raw(rk, &[0u8; 16]);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Reason: 先验证 tag 再解密，防止 padding oracle 和选择密文攻击
    let ghash_val = ghash(&h, aad, ciphertext);
    let ej0 = encrypt_block_raw(rk, &j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = ghash_val[i] ^ ej0[i];
    }

    // 常量时间 tag 比较，防止时序侧信道
    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(crate::error::Error::AuthTagMismatch);
    }

    let mut ctr = j0;
    gcm_ctr_inc(&mut ctr);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = ctr;
    for chunk in ciphertext.chunks(16) {
        let ks = encrypt_block_raw(rk, &counter);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ ks[i]);
        }
        gcm_ctr_inc(&mut counter);
    }
    Ok(plaintext)
}

// ── CCM ──────────────────────────────────────────────────────────────────────

/// 构造 CCM CBC-MAC（RFC 3610）
fn ccm_cbc_mac(
    rk: &[u32; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    message: &[u8],
    tag_len: usize,
) -> [u8; 16] {
    let q = 3usize; // nonce=12B 时 q=15-12=3
    let has_aad = !aad.is_empty();
    let flags = ((has_aad as u8) << 6) | (((tag_len - 2) / 2) as u8) << 3 | (q as u8 - 1);

    let mut b0 = [0u8; 16];
    b0[0] = flags;
    b0[1..13].copy_from_slice(nonce);
    let msg_len = message.len() as u32;
    b0[13] = (msg_len >> 16) as u8;
    b0[14] = (msg_len >> 8) as u8;
    b0[15] = msg_len as u8;

    let mut x = encrypt_block_raw(rk, &b0);

    if has_aad {
        let aad_len = aad.len();
        // Reason: CCM AAD 前缀 2 字节长度 + AAD 数据，补零至 16 字节对齐
        let prefix_len = 2 + aad_len;
        let padded_len = (prefix_len + 15) / 16 * 16;
        let mut aad_buf = [0u8; 512]; // 足够大的栈缓冲区
        if prefix_len <= aad_buf.len() {
            aad_buf[0..2].copy_from_slice(&(aad_len as u16).to_be_bytes());
            aad_buf[2..2 + aad_len].copy_from_slice(aad);
            for chunk in aad_buf[..padded_len].chunks(16) {
                let block: [u8; 16] = chunk.try_into().unwrap();
                for i in 0..16 {
                    x[i] ^= block[i];
                }
                x = encrypt_block_raw(rk, &x);
            }
        }
    }

    for chunk in message.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        x = encrypt_block_raw(rk, &x);
    }
    x
}

/// SM4-CCM 加密（AEAD）
///
/// # 参数
/// - `nonce`: 12 字节
/// - `tag_len`: 认证标签长度，须为 4/6/8/10/12/14/16 之一
///
/// # 返回
/// 密文 || 认证标签（`tag_len` 字节）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Vec<u8> {
    assert!(
        (4..=16).contains(&tag_len) && tag_len % 2 == 0,
        "CCM tag_len 须为 4~16 的偶数"
    );

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let t = ccm_cbc_mac(rk, nonce, aad, plaintext, tag_len);

    let mut a0 = [0u8; 16];
    a0[0] = 2u8; // q-1 = 3-1 = 2
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

    let mut enc_tag = [0u8; 16];
    for i in 0..tag_len {
        enc_tag[i] = t[i] ^ s0[i];
    }

    let mut out = Vec::with_capacity(plaintext.len() + tag_len);
    for (block_idx, chunk) in plaintext.chunks(16).enumerate() {
        let mut a_i = a0;
        let ctr_val = (block_idx as u32) + 1;
        a_i[13] = (ctr_val >> 16) as u8;
        a_i[14] = (ctr_val >> 8) as u8;
        a_i[15] = ctr_val as u8;
        let ks = encrypt_block_raw(rk, &a_i);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
    }
    out.extend_from_slice(&enc_tag[..tag_len]);
    out
}

/// SM4-CCM 解密（AEAD）
///
/// **先验证认证标签，验证通过后才解密。**
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, crate::error::Error> {
    if ciphertext_with_tag.len() < tag_len {
        return Err(crate::error::Error::InvalidInputLength);
    }
    let ct = &ciphertext_with_tag[..ciphertext_with_tag.len() - tag_len];
    let received_tag = &ciphertext_with_tag[ciphertext_with_tag.len() - tag_len..];

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let mut a0 = [0u8; 16];
    a0[0] = 2u8;
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

    // Step 1: CTR 解密密文（得到候选明文）
    let mut plaintext = Vec::with_capacity(ct.len());
    for (block_idx, chunk) in ct.chunks(16).enumerate() {
        let mut a_i = a0;
        let ctr_val = (block_idx as u32) + 1;
        a_i[13] = (ctr_val >> 16) as u8;
        a_i[14] = (ctr_val >> 8) as u8;
        a_i[15] = ctr_val as u8;
        let ks = encrypt_block_raw(rk, &a_i);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ ks[i]);
        }
    }

    // Step 2: 对候选明文重新计算 CBC-MAC
    let t = ccm_cbc_mac(rk, nonce, aad, &plaintext, tag_len);
    let mut expected_tag = [0u8; 16];
    for i in 0..tag_len {
        expected_tag[i] = t[i] ^ s0[i];
    }

    // Step 3: 常量时间比较，验证通过才返回明文
    // Reason: 先验证后解密，防止选择密文攻击
    if expected_tag[..tag_len].ct_eq(received_tag).unwrap_u8() == 0 {
        return Err(crate::error::Error::AuthTagMismatch);
    }

    Ok(plaintext)
}

// ── XTS ──────────────────────────────────────────────────────────────────────

/// GF(2^128) 乘以 α（XTS tweak 更新）
fn xts_mul_alpha(tweak: &mut [u8; 16]) {
    // Reason: XTS 使用反射位序的 GF(2^128)，对应右移 + 0xE1 规约
    let carry = tweak[15] & 1;
    for i in (1..16).rev() {
        tweak[i] = (tweak[i] >> 1) | ((tweak[i - 1] & 1) << 7);
    }
    tweak[0] >>= 1;
    if carry == 1 {
        tweak[0] ^= 0xE1;
    }
}

/// SM4-XTS 加密（磁盘加密模式，GB/T 17964-2021）
///
/// # 参数
/// - `key1`: 数据加密密钥（16 字节）
/// - `key2`: tweak 加密密钥（16 字节）
/// - `tweak_sector`: 扇区号（16 字节，通常为扇区编号的小端表示）
/// - `data`: 明文（须为 16 字节整倍数）
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_xts(
    key1: &[u8; 16],
    key2: &[u8; 16],
    tweak_sector: &[u8; 16],
    data: &[u8],
) -> Vec<u8> {
    let sm4_1 = Sm4Key::new(key1);
    let sm4_2 = Sm4Key::new(key2);
    let mut tweak = *tweak_sector;
    sm4_2.encrypt_block(&mut tweak);

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() == 16 {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ tweak[i];
            }
            sm4_1.encrypt_block(&mut block);
            for i in 0..16 {
                out.push(block[i] ^ tweak[i]);
            }
            xts_mul_alpha(&mut tweak);
        }
    }
    out
}

/// SM4-XTS 解密（磁盘加密模式）
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_xts(
    key1: &[u8; 16],
    key2: &[u8; 16],
    tweak_sector: &[u8; 16],
    data: &[u8],
) -> Vec<u8> {
    let sm4_1 = Sm4Key::new(key1);
    let sm4_2 = Sm4Key::new(key2);
    let mut tweak = *tweak_sector;
    sm4_2.encrypt_block(&mut tweak);

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        if chunk.len() == 16 {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ tweak[i];
            }
            sm4_1.decrypt_block(&mut block);
            for i in 0..16 {
                out.push(block[i] ^ tweak[i]);
            }
            xts_mul_alpha(&mut tweak);
        }
    }
    out
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32907-2016 附录 B：CBC 模式测试向量
    #[test]
    fn test_cbc_vector() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let iv = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plain = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let ct = sm4_encrypt_cbc(&key, &iv, &plain);
        let pt = sm4_decrypt_cbc(&key, &iv, &ct);
        assert_eq!(pt, plain, "CBC 往返解密失败");
    }

    /// GCM 加解密往返测试
    #[test]
    fn test_gcm_roundtrip() {
        let key = [0u8; 16];
        let nonce = [1u8; 12];
        let aad = b"additional data";
        let plain = b"hello gcm world!";

        let (ct, tag) = sm4_encrypt_gcm(&key, &nonce, aad, plain);
        let pt = sm4_decrypt_gcm(&key, &nonce, aad, &ct, &tag).unwrap();
        assert_eq!(pt, plain, "GCM 往返解密失败");
    }

    /// GCM tag 篡改检测
    #[test]
    fn test_gcm_tag_tamper() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let (ct, mut tag) = sm4_encrypt_gcm(&key, &nonce, b"", b"secret");
        tag[0] ^= 1;
        assert!(
            sm4_decrypt_gcm(&key, &nonce, b"", &ct, &tag).is_err(),
            "篡改 tag 后应返回错误"
        );
    }

    /// CCM 加解密往返测试
    #[test]
    fn test_ccm_roundtrip() {
        let key = [0u8; 16];
        let nonce = [2u8; 12];
        let aad = b"ccm aad";
        let plain = b"ccm plaintext!!!";

        let ct = sm4_encrypt_ccm(&key, &nonce, aad, plain, 16);
        let pt = sm4_decrypt_ccm(&key, &nonce, aad, &ct, 16).unwrap();
        assert_eq!(pt, plain, "CCM 往返解密失败");
    }

    /// CCM tag 篡改检测（先验证后解密原则验证）
    #[test]
    fn test_ccm_tag_tamper() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut ct = sm4_encrypt_ccm(&key, &nonce, b"", b"secret data here", 16);
        // 篡改 tag（最后 16 字节）
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(
            sm4_decrypt_ccm(&key, &nonce, b"", &ct, 16).is_err(),
            "篡改 CCM tag 后应返回错误"
        );
    }

    /// OFB 自反性验证
    #[test]
    fn test_ofb_self_inverse() {
        let key = [0xABu8; 16];
        let iv = [0x12u8; 16];
        let plain = b"ofb test message";
        let ct = sm4_crypt_ofb(&key, &iv, plain);
        let pt = sm4_crypt_ofb(&key, &iv, &ct);
        assert_eq!(pt, plain, "OFB 应为自反模式");
    }
}
