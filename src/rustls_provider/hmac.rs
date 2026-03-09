//! SM3-HMAC → rustls `crypto::hmac::Hmac` / `crypto::hmac::Key`

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::crypto::hmac;

use crate::sm3::HmacSm3;

/// 静态 HMAC-SM3 实现（传入 `HkdfUsingHmac`）
pub(crate) static HMAC_SM3: Sm3Hmac = Sm3Hmac;

pub(crate) struct Sm3Hmac;

impl hmac::Hmac for Sm3Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        Box::new(Sm3HmacKey { key: key.to_vec() })
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct Sm3HmacKey {
    key: Vec<u8>,
}

impl hmac::Key for Sm3HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        // Reason: rustls 将消息分为 first / middle / last 三段，
        //   用流式 HmacSm3 逐段喂入，避免额外拷贝和堆分配
        let mut mac = HmacSm3::new(&self.key);
        mac.update(first);
        for chunk in middle {
            mac.update(chunk);
        }
        mac.update(last);
        hmac::Tag::new(&mac.finalize())
    }

    fn tag_len(&self) -> usize {
        32
    }
}
