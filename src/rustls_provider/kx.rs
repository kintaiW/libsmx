//! SM2 ECDHE 密钥交换 → rustls `SupportedKxGroup` / `ActiveKeyExchange`

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::crypto::kx::{
    ActiveKeyExchange, NamedGroup, SharedSecret, StartedKeyExchange, SupportedKxGroup,
};
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
            rand_core::Error::from(
                NonZeroU32::new(e.raw_os_error().unwrap_or(1) as u32)
                    .unwrap_or(NonZeroU32::new(1).unwrap()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use rustls::crypto::kx::NamedGroup;

    use super::CURVE_SM2;

    #[test]
    fn test_name() {
        assert_eq!(CURVE_SM2.name(), NamedGroup::curveSM2);
    }

    #[test]
    fn test_ecdhe_roundtrip() {
        // 模拟 TLS 握手：A 生成临时密钥对，B 生成临时密钥对，双方计算共享密钥
        let kx_a = CURVE_SM2.start().unwrap().into_single();
        let kx_b = CURVE_SM2.start().unwrap().into_single();

        let pub_a = kx_a.pub_key().to_vec();
        let pub_b = kx_b.pub_key().to_vec();

        // 65 字节非压缩公钥（04 || x || y）
        assert_eq!(pub_a.len(), 65);
        assert_eq!(pub_b.len(), 65);
        assert_eq!(pub_a[0], 0x04);

        let secret_a = kx_a.complete(&pub_b).unwrap();
        let secret_b = kx_b.complete(&pub_a).unwrap();

        // 两端共享密钥必须相同（32 字节 x 坐标）
        assert_eq!(secret_a.secret_bytes(), secret_b.secret_bytes());
        assert_eq!(secret_a.secret_bytes().len(), 32);
    }

    #[test]
    fn test_invalid_peer_key_rejected() {
        let kx = CURVE_SM2.start().unwrap().into_single();
        // 无效公钥（全零）应报错
        let result = kx.complete(&[0u8; 65]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_ffdhe_group() {
        assert!(CURVE_SM2.ffdhe_group().is_none());
    }
}
