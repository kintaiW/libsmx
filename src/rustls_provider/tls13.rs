//! SM4-GCM/CCM AEAD + HKDF-SM3 → rustls TLS 1.3 密码套件

use alloc::boxed::Box;
use alloc::vec::Vec;

use rustls::crypto::cipher::{
    encode_record_header, make_tls13_aad, AeadKey, InboundOpaque, Iv, Nonce, OutboundPlain, Record,
    RecordDecrypter, RecordEncrypter, Tls13AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::CipherSuite;
use rustls::enums::ContentType;
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
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        Box::new(Sm4GcmEncrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
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

impl RecordEncrypter for Sm4GcmEncrypter {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let typ = ContentType::ApplicationData;
        let header = encode_record_header(typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        let aad = make_tls13_aad(typ, record.version.encode(), total_len);

        // TLS 1.3 inner plaintext = payload || inner ContentType，然后整体加密。
        let start = out.len();
        record.payload.copy_to_vec(out);
        out.extend_from_slice(&record.typ.to_array());
        let (ciphertext, tag) = sm4_encrypt_gcm(&self.key, &nonce, &aad, &out[start..]);
        out.truncate(start);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16 // +1 ContentType byte + 16 GCM tag
    }
}

struct Sm4GcmDecrypter {
    key: [u8; 16],
    iv: Iv,
}

impl RecordDecrypter for Sm4GcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        {
            let payload = &mut record.payload;
            if payload.len() < 16 {
                return Err(Error::DecryptError);
            }

            let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
            // Reason: AAD 使用解密前（含 tag）的完整 payload 长度
            let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());

            let ct_len = payload.len() - 16;
            let tag: [u8; 16] = payload[ct_len..]
                .try_into()
                .map_err(|_| Error::DecryptError)?;
            let plaintext = sm4_decrypt_gcm(&self.key, &nonce, &aad, &payload[..ct_len], &tag)
                .map_err(|_| Error::DecryptError)?;

            let plain_len = plaintext.len();
            payload[..plain_len].copy_from_slice(&plaintext);
            payload.truncate(plain_len);
        }
        record.into_tls13_unpadded_record()
    }
}

// ── SM4-CCM ───────────────────────────────────────────────────────────────────

struct Sm4CcmAead;

impl Tls13AeadAlgorithm for Sm4CcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        Box::new(Sm4CcmEncrypter {
            key: aead_key_to_16(&key),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
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

impl RecordEncrypter for Sm4CcmEncrypter {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let typ = ContentType::ApplicationData;
        let header = encode_record_header(typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);

        let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
        let aad = make_tls13_aad(typ, record.version.encode(), total_len);

        let start = out.len();
        record.payload.copy_to_vec(out);
        out.extend_from_slice(&record.typ.to_array());
        // sm4_encrypt_ccm 返回 ciphertext+tag 合并的 Vec
        let combined = sm4_encrypt_ccm(&self.key, &nonce, &aad, &out[start..], 16)
            .map_err(|_| Error::EncryptError)?;
        out.truncate(start);
        out.extend_from_slice(&combined);
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16
    }
}

struct Sm4CcmDecrypter {
    key: [u8; 16],
    iv: Iv,
}

impl RecordDecrypter for Sm4CcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        {
            let payload = &mut record.payload;
            if payload.len() < 16 {
                return Err(Error::DecryptError);
            }

            let nonce = Nonce::new(&self.iv, seq).to_array::<NONCE_LEN>()?;
            let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());

            // sm4_decrypt_ccm 接收 ciphertext_with_tag（末尾 tag_len 字节为 tag）
            let plaintext = sm4_decrypt_ccm(&self.key, &nonce, &aad, &payload[..], 16)
                .map_err(|_| Error::DecryptError)?;

            let plain_len = plaintext.len();
            payload[..plain_len].copy_from_slice(&plaintext);
            payload.truncate(plain_len);
        }
        record.into_tls13_unpadded_record()
    }
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

fn aead_key_to_16(key: &AeadKey) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&key.as_ref()[..16]);
    out
}
