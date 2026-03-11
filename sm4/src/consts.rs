//! SM4 S-box constants and internal cipher functions (GB/T 32907-2016).
//!
//! All operations are constant-time boolean-circuit implementations.

// ── System constants ──────────────────────────────────────────────────────────

/// System parameter FK (GB/T 32907 §A.1)
pub(super) const FK: [u32; 4] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

/// Constant key CK (GB/T 32907 §A.1)
#[rustfmt::skip]
pub(super) const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

// ── Boolean-circuit S-box ─────────────────────────────────────────────────────

/// SM4 S-box — pure boolean circuit (zero memory access, cache-timing immune).
///
/// Input/output linear layers + GF(2^4) inversion in boolean circuit form.
/// Source: emmansun/sm4bs (sbox64), extracted and validated against all 256 values.
///
/// ⚠️ Security: Uses only AND/XOR/OR/NOT. No table lookups, no memory reads.
#[allow(dead_code)]
#[inline]
pub(super) fn sbox_ct(x: u8) -> u8 {
    let b0 = x & 1;
    let b1 = (x >> 1) & 1;
    let b2 = (x >> 2) & 1;
    let b3 = (x >> 3) & 1;
    let b4 = (x >> 4) & 1;
    let b5 = (x >> 5) & 1;
    let b6 = (x >> 6) & 1;
    let b7 = (x >> 7) & 1;

    let t1 = b7 ^ b5;
    let t2 = 1 ^ (b5 ^ b1);
    let g5 = 1 ^ b0;
    let t3 = 1 ^ (b0 ^ t2);
    let t4 = b6 ^ b2;
    let t5 = b3 ^ t3;
    let t6 = b4 ^ t1;
    let t7 = b1 ^ t5;
    let t8 = b1 ^ t4;
    let t9 = t6 ^ t8;
    let t10 = t6 ^ t7;
    let t11 = 1 ^ (b3 ^ t1);
    let t12 = 1 ^ (b6 ^ t9);

    let g0 = t10;
    let g1 = t7;
    let g2 = t4 ^ t10;
    let g3 = t5;
    let g4 = t2;
    let g6 = t11 ^ t2;
    let g7 = t12 ^ (t11 ^ t2);
    let m0 = t6; let m1 = t3; let m2 = t8;
    let m3 = t3 ^ t12; let m4 = t4; let m5 = t11;
    let m6 = b1; let m7 = t11 ^ m3; let m8 = t9; let m9 = t12;

    let t2t = m0 & m1; let t3t = g0 & g4; let t4t = g3 & g7;
    let t7t = g3 | g7; let t11t = m4 & m5; let t10t = m3 & m2;
    let t12t = m3 | m2; let t6t = g6 | g2; let t9t = m6 | m7;
    let t5t = m8 & m9; let t8t = m8 | m9;
    let t14t = t3t ^ t2t; let t16t = t5t ^ t14t;
    let t20t = t16t ^ t7t; let t17t = t9t ^ t10t;
    let t18t = t11t ^ t12t;
    let p2 = t20t ^ t18t; let p0 = t6t ^ t16t;
    let t1t = g5 & g1; let t13t = t1t ^ t2t;
    let t15t = t13t ^ t4t;
    let p3 = (t6t ^ t15t) ^ t17t; let p1 = t8t ^ t15t;

    let t0m = p1 & p2; let t1m = p3 & p0; let t2m = p0 & p2;
    let t3m = p1 & p3; let t4m = t0m & t2m;
    let t5m = t1m ^ t3m; let t6m = t5m | p0; let t7m = t2m | p3;
    let l3 = t4m ^ t6m; let t9m = t7m ^ t3m;
    let l0 = t0m ^ t9m; let t11m = p2 | t5m;
    let l1 = t11m ^ t1m; let t12m = p1 | t2m; let l2 = t12m ^ t5m;

    let k4 = l2 ^ l3; let k3 = l1 ^ l3; let k2 = l0 ^ l2;
    let k0 = l0 ^ l1; let k1 = k2 ^ k3;

    let e0 = m1 & k0; let e1 = g5 & l1; let r0 = e0 ^ e1;
    let e2 = g4 & l0; let r1 = e2 ^ e1;
    let e3 = m7 & k3; let e4 = m5 & k2; let r2 = e3 ^ e4;
    let e5 = m3 & k1; let r3 = e5 ^ e4;
    let e6 = m9 & k4; let e7 = g7 & l3; let r4 = e6 ^ e7;
    let e8 = g6 & l2; let r5 = e8 ^ e7;
    let e9 = m0 & k0; let e10 = g1 & l1; let r6 = e9 ^ e10;
    let e11 = g0 & l0; let r7 = e11 ^ e10;
    let e12 = m6 & k3; let e13 = m4 & k2; let r8 = e12 ^ e13;
    let e14 = m2 & k1; let r9 = e14 ^ e13;
    let e15 = m8 & k4; let e16 = g3 & l3; let r10 = e15 ^ e16;
    let e17 = g2 & l2; let r11 = e17 ^ e16;

    let t1o = r7 ^ r9; let t2o = r1 ^ t1o; let t3o = r3 ^ t2o;
    let t4o = r5 ^ r3; let t5o = r4 ^ t4o; let t6o = r0 ^ r4;
    let t7o = r11 ^ r7;
    let b5o = t1o ^ t4o; let b2o = t1o ^ t6o;
    let t10o = r2 ^ t5o; let b3o = r10 ^ r8;
    let b1o = 1 ^ (t3o ^ b3o); let b6o = t10o ^ b1o;
    let b4o = 1 ^ (t3o ^ t7o); let b0o = t6o ^ b4o;
    let b7o = 1 ^ (r10 ^ r6);

    b0o | (b1o << 1) | (b2o << 2) | (b3o << 3) | (b4o << 4) | (b5o << 5) | (b6o << 6) | (b7o << 7)
}

/// SM4 τ transform: 4-byte u32 bitslice S-box (constant-time, 4-way parallel).
///
/// Packs 4 bytes' bit-planes into 4 u32 lanes, runs the boolean circuit once,
/// then unpacks — equivalent to ~3-4x speedup over 4 independent `sbox_ct` calls.
///
/// ⚠️ Security: Inherits full constant-time properties of `sbox_ct`.
#[inline]
pub(super) fn tau(a: u32) -> u32 {
    let bytes = a.to_be_bytes();

    // Pack: bits[i] low 4 = bit-i of [byte0, byte1, byte2, byte3]
    let mut bits = [0u32; 8];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = ((bytes[0] >> i) & 1) as u32
            | (((bytes[1] >> i) & 1) as u32) << 1
            | (((bytes[2] >> i) & 1) as u32) << 2
            | (((bytes[3] >> i) & 1) as u32) << 3;
    }
    let [b0, b1, b2, b3, b4, b5, b6, b7] = bits;

    // Boolean circuit (identical to sbox_ct, but NOT uses 0xF instead of 1)
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

    let g0 = t10; let g1 = t7; let g2 = t4 ^ t10; let g3 = t5;
    let g4 = t2; let g6 = t11 ^ t2; let g7 = t12 ^ (t11 ^ t2);
    let m0 = t6; let m1 = t3; let m2 = t8; let m3 = t3 ^ t12;
    let m4 = t4; let m5 = t11; let m6 = b1; let m7 = t11 ^ m3;
    let m8 = t9; let m9 = t12;

    let t2t = m0 & m1; let t3t = g0 & g4; let t4t = g3 & g7;
    let t7t = g3 | g7; let t11t = m4 & m5; let t10t = m3 & m2;
    let t12t = m3 | m2; let t6t = g6 | g2; let t9t = m6 | m7;
    let t5t = m8 & m9; let t8t = m8 | m9;
    let t14t = t3t ^ t2t; let t16t = t5t ^ t14t;
    let t20t = t16t ^ t7t; let t17t = t9t ^ t10t;
    let t18t = t11t ^ t12t;
    let p2 = t20t ^ t18t; let p0 = t6t ^ t16t;
    let t1t = g5 & g1; let t13t = t1t ^ t2t;
    let t15t = t13t ^ t4t;
    let p3 = (t6t ^ t15t) ^ t17t; let p1 = t8t ^ t15t;

    let t0m = p1 & p2; let t1m = p3 & p0; let t2m = p0 & p2;
    let t3m = p1 & p3; let t4m = t0m & t2m;
    let t5m = t1m ^ t3m; let t6m = t5m | p0; let t7m = t2m | p3;
    let l3 = t4m ^ t6m; let t9m = t7m ^ t3m;
    let l0 = t0m ^ t9m; let t11m = p2 | t5m;
    let l1 = t11m ^ t1m; let t12m = p1 | t2m; let l2 = t12m ^ t5m;

    let k4 = l2 ^ l3; let k3 = l1 ^ l3; let k2 = l0 ^ l2;
    let k0 = l0 ^ l1; let k1 = k2 ^ k3;

    let e0 = m1 & k0; let e1 = g5 & l1; let r0 = e0 ^ e1;
    let e2 = g4 & l0; let r1 = e2 ^ e1;
    let e3 = m7 & k3; let e4 = m5 & k2; let r2 = e3 ^ e4;
    let e5 = m3 & k1; let r3 = e5 ^ e4;
    let e6 = m9 & k4; let e7 = g7 & l3; let r4 = e6 ^ e7;
    let e8 = g6 & l2; let r5 = e8 ^ e7;
    let e9 = m0 & k0; let e10 = g1 & l1; let r6 = e9 ^ e10;
    let e11 = g0 & l0; let r7 = e11 ^ e10;
    let e12 = m6 & k3; let e13 = m4 & k2; let r8 = e12 ^ e13;
    let e14 = m2 & k1; let r9 = e14 ^ e13;
    let e15 = m8 & k4; let e16 = g3 & l3; let r10 = e15 ^ e16;
    let e17 = g2 & l2; let r11 = e17 ^ e16;

    let t1o = r7 ^ r9; let t2o = r1 ^ t1o; let t3o = r3 ^ t2o;
    let t4o = r5 ^ r3; let t5o = r4 ^ t4o; let t6o = r0 ^ r4;
    let t7o = r11 ^ r7;
    let b5o = t1o ^ t4o; let b2o = t1o ^ t6o;
    let t10o = r2 ^ t5o; let b3o = r10 ^ r8;
    let b1o = 0xF ^ (t3o ^ b3o); let b6o = t10o ^ b1o;
    let b4o = 0xF ^ (t3o ^ t7o); let b0o = t6o ^ b4o;
    let b7o = 0xF ^ (r10 ^ r6);

    // Unpack: 8 u32 low-4 bits -> 4 output bytes
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

// ── Round functions ───────────────────────────────────────────────────────────

/// Encryption round function T (GB/T 32907 §6.2.1)
#[inline]
pub(super) fn t_enc(a: u32) -> u32 {
    let b = tau(a);
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// Key expansion round function T' (GB/T 32907 §6.2.2)
#[inline]
fn t_key(a: u32) -> u32 {
    let b = tau(a);
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

// ── Key expansion ─────────────────────────────────────────────────────────────

/// SM4 key expansion (GB/T 32907 §6.2.2)
pub(super) fn expand_key(key: &[u8; 16], rk: &mut [u32; 32]) {
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

// ── Block load/store ──────────────────────────────────────────────────────────

#[inline]
pub(super) fn load_block(b: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u32::from_be_bytes(b[4..8].try_into().unwrap()),
        u32::from_be_bytes(b[8..12].try_into().unwrap()),
        u32::from_be_bytes(b[12..16].try_into().unwrap()),
    ]
}

#[inline]
pub(super) fn store_block(b: &mut [u8; 16], x: &[u32; 4]) {
    b[0..4].copy_from_slice(&x[0].to_be_bytes());
    b[4..8].copy_from_slice(&x[1].to_be_bytes());
    b[8..12].copy_from_slice(&x[2].to_be_bytes());
    b[12..16].copy_from_slice(&x[3].to_be_bytes());
}

// ── Encryption / Decryption rounds ────────────────────────────────────────────

/// 32-round SM4 encryption (round keys in forward order)
pub(super) fn encrypt_rounds(x: &mut [u32; 4], rk: &[u32; 32]) {
    for &rk_i in rk.iter() {
        let tmp = x[1] ^ x[2] ^ x[3] ^ rk_i;
        let next = x[0] ^ t_enc(tmp);
        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = next;
    }
    x.reverse(); // GB/T 32907 §6.2.1: output = (X35, X34, X33, X32)
}

/// 32-round SM4 decryption (round keys in reverse order)
pub(super) fn decrypt_rounds(x: &mut [u32; 4], rk: &[u32; 32]) {
    for i in (0..32).rev() {
        let tmp = x[1] ^ x[2] ^ x[3] ^ rk[i];
        let next = x[0] ^ t_enc(tmp);
        x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = next;
    }
    x.reverse();
}
