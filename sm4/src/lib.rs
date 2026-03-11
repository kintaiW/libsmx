//! SM4 block cipher (GB/T 32907-2016).
//!
//! This crate provides a [`cipher::BlockCipherEncrypt`] / [`cipher::BlockCipherDecrypt`]
//! compatible SM4 implementation suitable for use in the RustCrypto ecosystem.
//!
//! ## Security
//!
//! SM4 is standardised by the Chinese National Standard (GB/T 32907-2016).
//! This implementation uses a **boolean-circuit bitslice S-box** (zero memory
//! accesses) rather than a lookup table, making it immune to cache-timing
//! side-channel attacks.
//!
//! ## Usage
//!
//! ```rust
//! use sm4::Sm4;
//! use sm4::cipher::{BlockCipherEncrypt, BlockCipherDecrypt, KeyInit};
//!
//! let key = [0u8; 16];
//! let plaintext  = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
//! let expected   = [0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
//!                   0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46];
//!
//! let cipher = Sm4::new(&plaintext.into());
//! let mut block = plaintext.into();
//! cipher.encrypt_block(&mut block);
//! assert_eq!(block[..], expected[..]);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod consts;

pub use cipher::{self, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockSizeUser, InOut, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Key type alias ────────────────────────────────────────────────────────────

/// SM4 key type: 128 bits (16 bytes).
pub type Sm4Key = cipher::Key<Sm4>;

// ── Sm4 struct ────────────────────────────────────────────────────────────────

/// SM4 block cipher (GB/T 32907-2016).
///
/// Implements [`BlockCipherEncrypt`] and [`BlockCipherDecrypt`] from the
/// `cipher` crate. Construct with [`KeyInit::new`].
#[derive(Clone)]
pub struct Sm4 {
    /// 32 round keys derived from the 128-bit master key.
    rk: [u32; 32],
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        self.rk.zeroize();
    }
}

impl ZeroizeOnDrop for Sm4 {}

// ── KeySizeUser / BlockSizeUser / ParBlocksSizeUser ───────────────────────────

impl KeySizeUser for Sm4 {
    /// SM4 requires a 128-bit (16-byte) key.
    type KeySize = U16;
}

impl BlockSizeUser for Sm4 {
    /// SM4 operates on 128-bit (16-byte) blocks.
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4 {
    /// No parallel blocks: each block is processed independently.
    type ParBlocksSize = U1;
}

// ── KeyInit ───────────────────────────────────────────────────────────────────

impl KeyInit for Sm4 {
    fn new(key: &Sm4Key) -> Self {
        let mut rk = [0u32; 32];
        // Reason: Sm4Key = Array<u8, U16> which Derefs to [u8; 16] via as_slice().
        consts::expand_key(<&[u8; 16]>::try_from(key.as_slice()).unwrap(), &mut rk);
        Self { rk }
    }
}

// ── AlgorithmName / Debug ─────────────────────────────────────────────────────

impl AlgorithmName for Sm4 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4")
    }
}

impl fmt::Debug for Sm4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4 { ... }")
    }
}

// ── BlockCipherEncrypt ────────────────────────────────────────────────────────

impl BlockCipherEncrypt for Sm4 {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(&Sm4EncBackend(self));
    }
}

// ── BlockCipherDecrypt ────────────────────────────────────────────────────────

impl BlockCipherDecrypt for Sm4 {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(&Sm4DecBackend(self));
    }
}

// ── Encryption backend ────────────────────────────────────────────────────────

struct Sm4EncBackend<'a>(&'a Sm4);

impl BlockSizeUser for Sm4EncBackend<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4EncBackend<'_> {
    type ParBlocksSize = U1;
}

impl BlockCipherEncBackend for Sm4EncBackend<'_> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut x =
            consts::load_block(<&[u8; 16]>::try_from(block.get_in().as_slice()).unwrap());
        consts::encrypt_rounds(&mut x, &self.0.rk);
        consts::store_block(
            <&mut [u8; 16]>::try_from(block.get_out().as_mut_slice()).unwrap(),
            &x,
        );
    }
}

// ── Decryption backend ────────────────────────────────────────────────────────

struct Sm4DecBackend<'a>(&'a Sm4);

impl BlockSizeUser for Sm4DecBackend<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4DecBackend<'_> {
    type ParBlocksSize = U1;
}

impl BlockCipherDecBackend for Sm4DecBackend<'_> {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut x =
            consts::load_block(<&[u8; 16]>::try_from(block.get_in().as_slice()).unwrap());
        consts::decrypt_rounds(&mut x, &self.0.rk);
        consts::store_block(
            <&mut [u8; 16]>::try_from(block.get_out().as_mut_slice()).unwrap(),
            &x,
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use hex_literal::hex;

    /// GB/T 32907-2016 Appendix A, Example 1
    /// Key = 0123456789ABCDEFFEDCBA9876543210
    /// Plaintext  = 0123456789ABCDEFFEDCBA9876543210
    /// Ciphertext = 681EDF34D206965E86B3E94F536E4246
    #[test]
    fn test_vector_appendix_a() {
        let key        = hex!("0123456789ABCDEFFEDCBA9876543210");
        let plaintext  = hex!("0123456789ABCDEFFEDCBA9876543210");
        let ciphertext = hex!("681EDF34D206965E86B3E94F536E4246");

        let cipher = Sm4::new(&key.into());

        let mut block: Block<Sm4> = plaintext.into();
        cipher.encrypt_block(&mut block);
        assert_eq!(block[..], ciphertext[..], "encryption mismatch");

        cipher.decrypt_block(&mut block);
        assert_eq!(block[..], plaintext[..], "decryption mismatch");
    }

    /// GB/T 32907-2016 Appendix A, Example 2: 1 000 000 iterations
    /// Repeatedly encrypt the same plaintext 10^6 times.
    /// Result must be 595298C7C6FD271F0402F804C33D3F66.
    #[test]
    #[ignore = "slow (1M iterations)"]
    fn test_vector_1m_iterations() {
        let key      = hex!("0123456789ABCDEFFEDCBA9876543210");
        let expected = hex!("595298C7C6FD271F0402F804C33D3F66");

        let cipher = Sm4::new(&key.into());
        let mut block: Block<Sm4> = hex!("0123456789ABCDEFFEDCBA9876543210").into();

        for _ in 0..1_000_000 {
            cipher.encrypt_block(&mut block);
        }
        assert_eq!(block[..], expected[..]);
    }

    /// All-zero key, all-zero block: encrypt then decrypt must restore plaintext.
    #[test]
    fn test_all_zeros_roundtrip() {
        let key       = [0u8; 16];
        let plaintext = [0u8; 16];

        let cipher = Sm4::new(&key.into());
        let mut block: Block<Sm4> = plaintext.into();
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block[..], plaintext[..]);
    }

    /// Arbitrary key/plaintext: roundtrip must restore the original.
    #[test]
    fn test_roundtrip() {
        let key       = hex!("FEDCBA98765432100123456789ABCDEF");
        let plaintext = hex!("AABBCCDDEEFF00112233445566778899");

        let cipher = Sm4::new(&key.into());
        let mut block: Block<Sm4> = plaintext.into();

        cipher.encrypt_block(&mut block);
        assert_ne!(block[..], plaintext[..], "ciphertext must differ from plaintext");

        cipher.decrypt_block(&mut block);
        assert_eq!(block[..], plaintext[..], "roundtrip must restore plaintext");
    }
}
