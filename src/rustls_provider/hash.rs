//! SM3 → rustls `crypto::hash::Hash` / `crypto::hash::Context`

use alloc::boxed::Box;

use rustls::crypto::{self, HashAlgorithm};

use crate::sm3::Sm3Hasher;

/// 静态 SM3 哈希实现
pub(crate) static SM3: Sm3Hash = Sm3Hash;

pub(crate) struct Sm3Hash;

impl crypto::hash::Hash for Sm3Hash {
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Sm3Context(Sm3Hasher::new()))
    }

    fn hash(&self, data: &[u8]) -> crypto::hash::Output {
        crypto::hash::Output::new(&Sm3Hasher::digest(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        // Reason: SM3 尚无 IANA TLS HashAlgorithm 标准编号，暂用 Unknown(0x07)
        HashAlgorithm::Unknown(0x07)
    }
}

struct Sm3Context(Sm3Hasher);

impl crypto::hash::Context for Sm3Context {
    fn fork_finish(&self) -> crypto::hash::Output {
        crypto::hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Sm3Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        crypto::hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hash::Hash;

    use super::SM3;

    // GB/T 32905 标准向量："abc" → SM3 哈希
    const ABC_DIGEST: &[u8] = &[
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4,
        0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b,
        0xa8, 0xe0,
    ];

    #[test]
    fn test_hash_abc() {
        let out = SM3.hash(b"abc");
        assert_eq!(out.as_ref(), ABC_DIGEST);
    }

    #[test]
    fn test_context_update_finish() {
        let mut ctx = SM3.start();
        ctx.update(b"ab");
        ctx.update(b"c");
        let out = ctx.finish();
        assert_eq!(out.as_ref(), ABC_DIGEST);
    }

    #[test]
    fn test_context_fork_finish() {
        let mut ctx = SM3.start();
        ctx.update(b"abc");
        // fork_finish 不消耗 ctx，fork 后原 ctx 可继续 finish
        let out1 = ctx.fork_finish();
        let out2 = ctx.finish();
        assert_eq!(out1.as_ref(), ABC_DIGEST);
        assert_eq!(out2.as_ref(), ABC_DIGEST);
    }

    #[test]
    fn test_context_fork() {
        let mut ctx = SM3.start();
        ctx.update(b"abc");
        let forked = ctx.fork();
        let out1 = forked.finish();
        let out2 = ctx.finish();
        assert_eq!(out1.as_ref(), ABC_DIGEST);
        assert_eq!(out2.as_ref(), ABC_DIGEST);
    }

    #[test]
    fn test_output_len() {
        assert_eq!(SM3.output_len(), 32);
    }
}
