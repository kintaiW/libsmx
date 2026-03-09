//! SM2 ECDHE 密钥交换 → rustls `SupportedKxGroup` / `ActiveKeyExchange`

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::crypto::kx::{ActiveKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange, SupportedKxGroup};
use rustls::error::{Error, PeerMisbehaved};

use crate::sm2::{generate_keypair, key_exchange::ecdh_from_slice, PrivateKey};

/// SM2 ECDHE 密钥交换组（RFC 8998 curveSM2）
pub static CURVE_SM2: &dyn SupportedKxGroup = &Sm2KxGroup;

#[derive(Debug)]
struct Sm2KxGroup;

impl SupportedKxGroup for Sm2KxGroup {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        // 使用 getrandom 生成随机标量
        let mut rng = Sm2Rng;
        let (private_key, pub_key_bytes) = generate_keypair(&mut rng);
        Ok(StartedKeyExchange::Single(Box::new(Sm2KeyExchange {
            private_key,
            pub_key: pub_key_bytes.to_vec(),
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::curveSM2
    }
}

struct Sm2KeyExchange {
    private_key: PrivateKey,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for Sm2KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // 标准 ECDHE：SM2 曲线标量乘法，输出共享密钥 x 坐标（32 字节）
        let shared = ecdh_from_slice(&self.private_key, peer_pub_key)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(shared.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::curveSM2
    }
}

// ── 内部 RNG 包装（使用 getrandom）────────────────────────────────────────────

pub(crate) struct Sm2Rng;

impl rand_core::RngCore for Sm2Rng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).expect("getrandom failed");
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| {
            // Reason: rand_core::Error::new 接受 NonZeroU32，直接用 getrandom 错误码
            use core::num::NonZeroU32;
            rand_core::Error::from(NonZeroU32::new(e.raw_os_error().unwrap_or(1) as u32).unwrap_or(NonZeroU32::new(1).unwrap()))
        })
    }
}
