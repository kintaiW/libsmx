//! SM4-GCM / SM4-CCM AEAD 实现（rustls TLS 1.3 专用）
//!
//! 此模块仅供 `rustls_provider` 内部使用，不对外公开。
//! GCM/CCM 是 TLS 1.3 密码套件的必要组成，与通用工作模式不同，
//! 它们与 TLS 记录层协议强耦合，因此保留在 rustls_provider 内。

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use subtle::ConstantTimeEq;

use crate::sm4::cipher::{encrypt_block_raw, Sm4Key};
use crate::error::Error;

// ── GF(2^128) 乘法 ────────────────────────────────────────────────────────────

/// GF(2^128) 乘法（NIST SP 800-38D Algorithm 1，常量时间，u64 优化）
///
/// Reason: GHASH 密钥 H 来自 SM4_K(0^128)，属秘密值；使用掩码算术替代
/// 条件分支，消除 cache-timing 和 branch-timing 侧信道。
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u64; 2];
    let mut v = [
        u64::from_be_bytes(y[0..8].try_into().unwrap()),
        u64::from_be_bytes(y[8..16].try_into().unwrap()),
    ];

    for &byte_xi in x.iter() {
        for bit_idx in (0..8).rev() {
            let mask = 0u64.wrapping_sub(((byte_xi >> bit_idx) & 1) as u64);
            z[0] ^= v[0] & mask;
            z[1] ^= v[1] & mask;

            let lsb = v[1] & 1;
            let carry = v[0] & 1;
            v[0] >>= 1;
            v[1] = (v[1] >> 1) | (carry << 63);
            let reduce_mask = 0u64.wrapping_sub(lsb);
            v[0] ^= 0xE100_0000_0000_0000u64 & reduce_mask;
        }
    }

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&z[0].to_be_bytes());
    out[8..16].copy_from_slice(&z[1].to_be_bytes());
    out
}

/// GHASH 认证函数（NIST SP 800-38D §6.4）
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 { y[i] ^= block[i]; }
        y = gf128_mul(&y, h);
    }
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 { y[i] ^= block[i]; }
        y = gf128_mul(&y, h);
    }
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    for i in 0..16 { y[i] ^= len_block[i]; }
    gf128_mul(&y, h)
}

/// GCM 计数器递增（仅最后 4 字节，GCM 标准）
#[inline]
fn gcm_ctr_inc(counter: &mut [u8; 16]) {
    // Reason: GCM 规范中计数器字段只占最后 4 字节（大端 32 位）
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 { break; }
    }
}

// ── GCM ───────────────────────────────────────────────────────────────────────

/// SM4-GCM 加密（AEAD），返回 `(密文, 16字节认证标签)`
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
    for i in 0..16 { tag[i] = ghash_val[i] ^ ej0[i]; }

    (ciphertext, tag)
}

/// SM4-GCM 解密（AEAD），先验证 tag 再解密
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
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
    for i in 0..16 { expected_tag[i] = ghash_val[i] ^ ej0[i]; }

    if expected_tag.ct_eq(tag).unwrap_u8() == 0 {
        return Err(Error::AuthTagMismatch);
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

// ── CCM ───────────────────────────────────────────────────────────────────────

/// 构造 CCM CBC-MAC（RFC 3610）
fn ccm_cbc_mac(
    rk: &[u32; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    message: &[u8],
    tag_len: usize,
) -> Result<[u8; 16], Error> {
    let q = 3usize;
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
        let prefix_len = 2 + aad_len;
        let padded_len = prefix_len.div_ceil(16) * 16;
        let mut aad_buf = [0u8; 512];

        // Reason: 超过 510 字节需要 4 字节长度编码（RFC 3610 §2.2），
        // 当前实现仅支持 2 字节编码，超限时必须拒绝而非静默跳过 AAD。
        if prefix_len > aad_buf.len() {
            return Err(Error::InvalidInputLength);
        }

        aad_buf[0..2].copy_from_slice(&(aad_len as u16).to_be_bytes());
        aad_buf[2..2 + aad_len].copy_from_slice(aad);
        for chunk in aad_buf[..padded_len].chunks(16) {
            let block: [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 { x[i] ^= block[i]; }
            x = encrypt_block_raw(rk, &x);
        }
    }

    for chunk in message.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 { x[i] ^= block[i]; }
        x = encrypt_block_raw(rk, &x);
    }
    Ok(x)
}

/// SM4-CCM 加密（AEAD），输出 `密文 || tag`
#[cfg(feature = "alloc")]
pub fn sm4_encrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    assert!(
        (4..=16).contains(&tag_len) && tag_len % 2 == 0,
        "CCM tag_len 须为 4~16 的偶数"
    );

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let t = ccm_cbc_mac(rk, nonce, aad, plaintext, tag_len)?;

    let mut a0 = [0u8; 16];
    a0[0] = 2u8;
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

    let mut enc_tag = [0u8; 16];
    for i in 0..tag_len { enc_tag[i] = t[i] ^ s0[i]; }

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
    Ok(out)
}

/// SM4-CCM 解密（AEAD），先验证 tag 再返回明文
#[cfg(feature = "alloc")]
pub fn sm4_decrypt_ccm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    if ciphertext_with_tag.len() < tag_len {
        return Err(Error::InvalidInputLength);
    }
    let ct = &ciphertext_with_tag[..ciphertext_with_tag.len() - tag_len];
    let received_tag = &ciphertext_with_tag[ciphertext_with_tag.len() - tag_len..];

    let sm4 = Sm4Key::new(key);
    let rk = sm4.round_keys();

    let mut a0 = [0u8; 16];
    a0[0] = 2u8;
    a0[1..13].copy_from_slice(nonce);
    let s0 = encrypt_block_raw(rk, &a0);

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

    let t = ccm_cbc_mac(rk, nonce, aad, &plaintext, tag_len)?;
    let mut expected_tag = [0u8; 16];
    for i in 0..tag_len { expected_tag[i] = t[i] ^ s0[i]; }

    // Reason: 先验证后解密，防止选择密文攻击
    if expected_tag[..tag_len].ct_eq(received_tag).unwrap_u8() == 0 {
        return Err(Error::AuthTagMismatch);
    }

    Ok(plaintext)
}
