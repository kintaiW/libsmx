//! SM3 cryptographic hash function (GB/T 32905-2016).
//!
//! This crate provides a [`Digest`]-compatible SM3 implementation suitable for
//! use anywhere in the RustCrypto ecosystem.
//!
//! ## Security
//!
//! SM3 is standardised by the Chinese National Standard (GB/T 32905-2016) and
//! provides a 256-bit (32-byte) digest.  It has a similar structure to SHA-256
//! but uses different constants, mixing functions, and message scheduling.
//!
//! ## Usage
//!
//! ```rust
//! use sm3::{Sm3, Digest};
//!
//! let hash = Sm3::digest(b"abc");
//! assert_eq!(
//!     hash[..],
//!     hex_literal::hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
//! );
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod compress;

/// Block-level SM3 core — low-level building block, not for direct use.
///
/// Prefer the top-level [`Sm3`] type which provides the full `Digest` API.
pub mod block_api;

pub use digest::{self, Digest};

// Re-export the core type for users who need low-level access (e.g. HMAC cores).
pub use block_api::Sm3Core;

// Generate the buffered `Sm3` wrapper using the digest crate macro.
// BaseFixedTraits provides: Debug, BlockSizeUser, OutputSizeUser, CoreProxy, Update, FixedOutput.
// We also add AlgorithmName, Default, Clone, HashMarker, Reset, FixedOutputReset explicitly.
// Reason: FixedHashTraits additionally requires SerializableState and ZeroizeOnDrop which
// are non-trivial to implement safely; BaseFixedTraits is sufficient for the Digest interface.
digest::buffer_fixed!(
    /// SM3 hash function (GB/T 32905-2016).
    ///
    /// Implements [`Digest`] and is a drop-in for SHA-256 in generic protocols.
    pub struct Sm3(block_api::Sm3Core);
    impl: BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset;
);

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use hex_literal::hex;

    /// GB/T 32905-2016 Appendix A, Example 1: SM3("abc")
    #[test]
    fn test_vector_abc() {
        let hash = Sm3::digest(b"abc");
        let expected = hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        assert_eq!(hash[..], expected[..]);
    }

    /// GB/T 32905-2016 Appendix A, Example 2: 64-byte repeated string
    #[test]
    fn test_vector_64bytes() {
        let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let hash = Sm3::digest(msg);
        let expected = hex!("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
        assert_eq!(hash[..], expected[..]);
    }

    /// Empty input
    #[test]
    fn test_vector_empty() {
        let hash = Sm3::digest(b"");
        let expected = hex!("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
        assert_eq!(hash[..], expected[..]);
    }

    /// Cross-block boundary: 65 bytes (one full block + 1 byte tail)
    #[test]
    fn test_cross_block_boundary() {
        let data = [0x61u8; 65]; // 65 x 'a'
        let once = Sm3::digest(&data);

        // Streaming 1 byte at a time must match one-shot
        let mut h = Sm3::new();
        for b in &data {
            h.update(&[*b]);
        }
        assert_eq!(once, h.finalize());
    }

    /// Streaming must match one-shot for an arbitrary input
    #[test]
    fn test_streaming_matches_oneshot() {
        let data = b"hello world, streaming SM3 test";
        let once = Sm3::digest(data);

        let mut h = Sm3::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(once, h.finalize());
    }

    /// Clone mid-stream must produce the same result
    #[test]
    fn test_clone_midstream() {
        let mut h1 = Sm3::new();
        h1.update(b"hello");
        let h2 = h1.clone();
        h1.update(b" world");

        let mut h3 = h2;
        h3.update(b" world");

        assert_eq!(h1.finalize(), h3.finalize());
    }
}
