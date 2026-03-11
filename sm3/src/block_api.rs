//! SM3 block-level core (low-level internal type).
//!
//! Users should use [`Sm3`] from the crate root instead.

use core::fmt;
use digest::{
    HashMarker,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser,
        Eager, FixedOutputCore, OutputSizeUser, UpdateCore,
    },
    typenum::{U32, U64, Unsigned},
};

use crate::compress;

// ── Sm3Core ───────────────────────────────────────────────────────────────────

/// Low-level SM3 block-processing core.
///
/// Implements the `digest::block_api` low-level traits so that the
/// [`digest::buffer_fixed!`] macro can wrap it into a fully-featured [`Sm3`].
#[derive(Clone)]
pub struct Sm3Core {
    state: [u32; 8],
    /// Number of **complete** 64-byte blocks already compressed.
    block_len: u64,
}

impl HashMarker for Sm3Core {}

impl BlockSizeUser for Sm3Core {
    /// SM3 processes 512-bit (64-byte) blocks.
    type BlockSize = U64;
}

impl BufferKindUser for Sm3Core {
    /// Eager: compress each full block immediately.
    type BufferKind = Eager;
}

impl OutputSizeUser for Sm3Core {
    /// SM3 produces a 256-bit (32-byte) digest.
    type OutputSize = U32;
}

impl Default for Sm3Core {
    fn default() -> Self {
        Self { state: compress::IV, block_len: 0 }
    }
}

impl digest::Reset for Sm3Core {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl UpdateCore for Sm3Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Reason: only complete blocks are counted here; the partial tail is
        // held by the surrounding BlockBuffer and counted in finalize.
        self.block_len += blocks.len() as u64;
        for block in blocks {
            // Reason: hybrid_array::Array<u8, U64> implements Deref<Target=[u8]>,
            // so we get a &[u8] slice then cast to &[u8; 64] via try_into.
            let b: &[u8; 64] = (&**block).try_into().unwrap();
            compress::compress(&mut self.state, b);
        }
    }
}

impl FixedOutputCore for Sm3Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut digest::Output<Self>) {
        // Total bit length = (complete blocks × 64 + partial tail) × 8
        let bs = U64::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        // GB/T 32905 §5.3.1 padding: 0x80, zeros, 64-bit big-endian bit count
        buffer.len64_padding_be(bit_len, |block| {
            let b: &[u8; 64] = (&**block).try_into().unwrap();
            compress::compress(&mut self.state, b);
        });

        // Serialize state as big-endian u32 words
        for (chunk, &word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sm3Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm3")
    }
}
