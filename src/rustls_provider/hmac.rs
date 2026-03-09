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

#[cfg(test)]
mod tests {
    use rustls::crypto::hmac::Hmac;

    use super::HMAC_SM3;

    // RFC 2104 HMAC-SM3 已知正确值（用 libsmx hmac_sm3 预计算）
    // key = b"key", data = b"The quick brown fox jumps over the lazy dog"
    // 通过 crate::sm3::hmac_sm3 验证
    fn reference_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        crate::sm3::hmac_sm3(key, data)
    }

    #[test]
    fn test_sign_concat_single_chunk() {
        let key = b"secret";
        let data = b"hello world";
        let k = HMAC_SM3.with_key(key);
        let tag = k.sign_concat(data, &[], &[]);
        assert_eq!(tag.as_ref(), reference_hmac(key, data));
    }

    #[test]
    fn test_sign_concat_split_matches_whole() {
        // 分段 "hel" + ["lo "] + "world" 应与整体 "hello world" 结果相同
        let key = b"secret";
        let k = HMAC_SM3.with_key(key);
        let tag = k.sign_concat(b"hel", &[b"lo "], b"world");
        assert_eq!(tag.as_ref(), reference_hmac(key, b"hello world"));
    }

    #[test]
    fn test_tag_len() {
        let k = HMAC_SM3.with_key(b"k");
        assert_eq!(k.tag_len(), 32);
    }
}
