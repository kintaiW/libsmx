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
