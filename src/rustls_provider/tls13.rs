//! SM4-GCM/CCM AEAD + HKDF-SM3 → rustls TLS 1.3 密码套件

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, EncodedMessage, InboundOpaque, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaque, OutboundPlain, Tls13AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::CipherSuite;
use rustls::enums::{ContentType, ProtocolVersion};
use rustls::error::Error;
use rustls::version::TLS13_VERSION;
use rustls::{CipherSuiteCommon, ConnectionTrafficSecrets, Tls13CipherSuite};

use crate::sm4::{sm4_decrypt_ccm, sm4_decrypt_gcm, sm4_encrypt_ccm, sm4_encrypt_gcm};

// ── HKDF（零代码复用 rustls 内置 HkdfUsingHmac）──────────────────────────────

pub(crate) static HKDF_SM3: HkdfUsingHmac<'static> = HkdfUsingHmac(&super::hmac::HMAC_SM3);

// ── TLS 1.3 密码套件常量 ──────────────────────────────────────────────────────

/// TLS 1.3 SM4-GCM-SM3 密码套件（RFC 8998）
pub static TLS13_SM4_GCM_SM3: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_SM4_GCM_SM3,
        hash_provider: &super::hash::SM3,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &HKDF_SM3,
    aead_alg: &Sm4GcmAead,
    quic: None,
};

/// TLS 1.3 SM4-CCM-SM3 密码套件（RFC 8998）
pub static TLS13_SM4_CCM_SM3: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_SM4_CCM_SM3,
        hash_provider: &super::hash::SM3,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &HKDF_SM3,
    aead_alg: &Sm4CcmAead,
    quic: None,
};

// ── SM4-GCM ───────────────────────────────────────────────────────────────────

struct Sm4GcmAead;

impl Tls13AeadAlgorithm for Sm4GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Sm4GcmEncrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Sm4GcmDecrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Sm4Gcm { key, iv })
    }
}

struct Sm4GcmEncrypter {
    key: [u8; 16],
    iv: Iv,
}

impl MessageEncrypter for Sm4GcmEncrypter {
    fn encrypt(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        let aad = make_tls13_aad(total_len);

        // 收集明文 + ContentType（TLS 1.3 inner plaintext 格式）
        let mut plaintext: Vec<u8> = Vec::with_capacity(msg.payload.len() + 1);
        {
            let mut tmp = OutboundOpaque::with_capacity(msg.payload.len() + 1);
            tmp.extend_from_chunks(&msg.payload);
            tmp.extend_from_slice(&msg.typ.to_array());
            plaintext.extend_from_slice(tmp.as_ref());
        }

        let (ciphertext, tag) = sm4_encrypt_gcm(&self.key, &nonce, &aad, &plaintext);

        let mut out = OutboundOpaque::with_capacity(ciphertext.len() + 16);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);

        Ok(EncodedMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: out,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16 // +1 ContentType byte + 16 GCM tag
    }
}

struct Sm4GcmDecrypter {
    key: [u8; 16],
    iv: Iv,
}

impl MessageDecrypter for Sm4GcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < 16 {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        // Reason: AAD 使用解密前（含 tag）的完整 payload 长度
        let aad = make_tls13_aad(payload.len());

        let ct_len = payload.len() - 16;
        let tag: [u8; 16] = payload[ct_len..]
            .try_into()
            .map_err(|_| Error::DecryptError)?;
        let plaintext = sm4_decrypt_gcm(&self.key, &nonce, &aad, &payload[..ct_len], &tag)
            .map_err(|_| Error::DecryptError)?;

        // 将明文写回 payload（in-place），然后截断
        let plain_len = plaintext.len();
        payload[..plain_len].copy_from_slice(&plaintext);
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

// ── SM4-CCM ───────────────────────────────────────────────────────────────────

struct Sm4CcmAead;

impl Tls13AeadAlgorithm for Sm4CcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Sm4CcmEncrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Sm4CcmDecrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Sm4Ccm { key, iv })
    }
}

struct Sm4CcmEncrypter {
    key: [u8; 16],
    iv: Iv,
}

impl MessageEncrypter for Sm4CcmEncrypter {
    fn encrypt(
        &mut self,
        msg: EncodedMessage<OutboundPlain<'_>>,
        seq: u64,
    ) -> Result<EncodedMessage<OutboundOpaque>, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        let aad = make_tls13_aad(total_len);

        let mut plaintext: Vec<u8> = Vec::with_capacity(msg.payload.len() + 1);
        {
            let mut tmp = OutboundOpaque::with_capacity(msg.payload.len() + 1);
            tmp.extend_from_chunks(&msg.payload);
            tmp.extend_from_slice(&msg.typ.to_array());
            plaintext.extend_from_slice(tmp.as_ref());
        }

        // sm4_encrypt_ccm 返回 ciphertext+tag 合并的 Vec
        let combined = sm4_encrypt_ccm(&self.key, &nonce, &aad, &plaintext, 16)
            .map_err(|_| Error::EncryptError)?;

        let mut out = OutboundOpaque::with_capacity(combined.len());
        out.extend_from_slice(&combined);

        Ok(EncodedMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: out,
        })
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16
    }
}

struct Sm4CcmDecrypter {
    key: [u8; 16],
    iv: Iv,
}

impl MessageDecrypter for Sm4CcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: EncodedMessage<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<EncodedMessage<&'a [u8]>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < 16 {
            return Err(Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        let aad = make_tls13_aad(payload.len());

        // sm4_decrypt_ccm 接收 ciphertext_with_tag（末尾 tag_len 字节为 tag）
        let plaintext = sm4_decrypt_ccm(&self.key, &nonce, &aad, &payload[..], 16)
            .map_err(|_| Error::DecryptError)?;

        let plain_len = plaintext.len();
        payload[..plain_len].copy_from_slice(&plaintext);
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

fn aead_key_to_16(key: &AeadKey) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&key.as_ref()[..16]);
    out
}
