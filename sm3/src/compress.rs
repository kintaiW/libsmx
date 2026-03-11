//! SM3 compression function (GB/T 32905-2016 §5)

/// SM3 initial hash values (IV), GB/T 32905 §4.3
pub(super) const IV: [u32; 8] = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

/// Round constants T_j (GB/T 32905 §4.2), precomputed to avoid runtime branches.
///
/// Reason: Eliminates the `if j < 16` branch in each round; the compiler
/// embeds these as immediates with zero runtime rotation overhead.
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

/// Permutation function P0 (GB/T 32905 §4.5)
#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// Permutation function P1 (GB/T 32905 §4.5)
#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// SM3 compression function: processes one 64-byte block, updates `state`.
///
/// Reason: Two-segment loop (j=0..15 and j=16..63) eliminates runtime `if`
/// branches inside ff/gg/T; W' is inlined as `w[j] ^ w[j+4]`.
pub(super) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // ── Message expansion ────────────────────────────────────────────────────
    let mut w = [0u32; 68];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..68 {
        let v = w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15);
        w[i] = p1(v) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
    }

    // ── Compression: 64 rounds ───────────────────────────────────────────────
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // j = 0..15: FF = x^y^z, GG = x^y^z
    for j in 0..16 {
        let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(T[j]).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = (a ^ b ^ c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = (e ^ f ^ g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c; c = b.rotate_left(9); b = a; a = tt1;
        h = g; g = f.rotate_left(19); f = e; e = p0(tt2);
    }

    // j = 16..63: FF = majority(x,y,z), GG = choice(x,y,z)
    for j in 16..64 {
        let ss1 = a.rotate_left(12).wrapping_add(e).wrapping_add(T[j]).rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = ((a & b) | (a & c) | (b & c))
            .wrapping_add(d).wrapping_add(ss2).wrapping_add(w[j] ^ w[j + 4]);
        let tt2 = ((e & f) | (!e & g))
            .wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j]);
        d = c; c = b.rotate_left(9); b = a; a = tt1;
        h = g; g = f.rotate_left(19); f = e; e = p0(tt2);
    }

    state[0] ^= a; state[1] ^= b; state[2] ^= c; state[3] ^= d;
    state[4] ^= e; state[5] ^= f; state[6] ^= g; state[7] ^= h;
}
