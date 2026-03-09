//! SM2 签名 → rustls `SigningKey` / `Signer`

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::crypto::{SignatureScheme, Signer, SigningKey};
use rustls::error::Error;

use crate::sm2::{
    der::{public_key_to_spki_der, sig_to_der},
    sign_message, PrivateKey, DEFAULT_ID,
};

/// 从 DER 编码的私钥加载 SM2 签名密钥
pub(crate) fn load_private_key(
    key_der: PrivateKeyDer<'static>,
) -> Result<Box<dyn SigningKey>, Error> {
    let pri_key = match &key_der {
        PrivateKeyDer::Sec1(sec1) => {
            crate::sm2::der::private_key_from_sec1_der(sec1.secret_sec1_der())
                .map_err(|_| Error::General("invalid SEC1 SM2 private key".into()))?
        }
        PrivateKeyDer::Pkcs8(pkcs8) => {
            crate::sm2::der::private_key_from_pkcs8_der(pkcs8.secret_pkcs8_der())
                .map_err(|_| Error::General("invalid PKCS#8 SM2 private key".into()))?
        }
        _ => return Err(Error::General("unsupported SM2 key format".into())),
    };
    Ok(Box::new(Sm2SigningKey { pri_key }))
}

struct Sm2SigningKey {
    pri_key: PrivateKey,
}

impl fmt::Debug for Sm2SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm2SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey for Sm2SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::SM2_SM3) {
            Some(Box::new(Sm2Signer {
                pri_key: self.pri_key.clone(),
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let pub_key_bytes = self.pri_key.public_key();
        let spki = public_key_to_spki_der(&pub_key_bytes);
        Some(SubjectPublicKeyInfoDer::from(spki))
    }
}

struct Sm2Signer {
    pri_key: PrivateKey,
}

impl fmt::Debug for Sm2Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sm2Signer").finish_non_exhaustive()
    }
}

impl Signer for Sm2Signer {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = super::kx::Sm2Rng;
        // GB/T 32918.2: 签名 = SM3(Z || M)，Z 由 ID 和公钥派生
        let sig_raw = sign_message(message, DEFAULT_ID, &self.pri_key, &mut rng);
        // TLS 传输使用 DER 编码签名
        Ok(sig_to_der(&sig_raw))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::SM2_SM3
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use rustls::crypto::SignatureScheme;

    use super::load_private_key;
    use crate::sm2::{der::sig_from_der, generate_keypair, verify_message, PrivateKey, DEFAULT_ID};

    /// 将 SM2 私钥编码为最小 SEC1 DER（无可选字段）
    /// ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING(32B) }
    fn encode_sec1_der(pri_key: &PrivateKey) -> Vec<u8> {
        let key_bytes = pri_key.as_bytes();
        // SEQUENCE body = INTEGER(1)[3B] + OCTET STRING(32B)[34B] = 37 字节
        let mut der = Vec::with_capacity(39);
        der.extend_from_slice(&[
            0x30, 0x25, // SEQUENCE, length 37
            0x02, 0x01, 0x01, // INTEGER(1) = version
            0x04, 0x20, // OCTET STRING, length 32
        ]);
        der.extend_from_slice(key_bytes);
        der
    }

    fn make_test_key_der() -> (PrivateKey, [u8; 65], pki_types::PrivateKeyDer<'static>) {
        let mut rng = super::super::kx::Sm2Rng;
        let (pri_key, pub_key) = generate_keypair(&mut rng);
        let sec1 = encode_sec1_der(&pri_key);
        let key_der = pki_types::PrivateKeyDer::Sec1(pki_types::PrivateSec1KeyDer::from(sec1));
        (pri_key, pub_key, key_der)
    }

    #[test]
    fn test_choose_scheme_sm2_sm3() {
        let (_, _, key_der) = make_test_key_der();
        let signing_key = load_private_key(key_der).unwrap();
        let signer = signing_key.choose_scheme(&[SignatureScheme::SM2_SM3]);
        assert!(signer.is_some());
        assert_eq!(signer.unwrap().scheme(), SignatureScheme::SM2_SM3);
    }

    #[test]
    fn test_choose_scheme_unmatched_returns_none() {
        let (_, _, key_der) = make_test_key_der();
        let signing_key = load_private_key(key_der).unwrap();
        // 不含 SM2_SM3 时应返回 None
        let signer = signing_key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256]);
        assert!(signer.is_none());
    }

    #[test]
    fn test_public_key_is_spki() {
        let (_, _, key_der) = make_test_key_der();
        let signing_key = load_private_key(key_der).unwrap();
        let spki = signing_key.public_key();
        assert!(spki.is_some());
        // SPKI DER 以 SEQUENCE (0x30) 开头
        let spki_bytes: &[u8] = spki.as_ref().unwrap().as_ref();
        assert_eq!(spki_bytes[0], 0x30);
        // 完整 SM2 SPKI：alg(21B) + BIT STRING(68B) = 89B，外层 SEQUENCE header(2B) = 91B
        assert_eq!(spki_bytes.len(), 91);
    }

    #[test]
    fn test_sign_produces_valid_der_signature() {
        let (_, pub_key, key_der) = make_test_key_der();
        let signing_key = load_private_key(key_der).unwrap();

        let signer = signing_key
            .choose_scheme(&[SignatureScheme::SM2_SM3])
            .unwrap();
        let message = b"hello SM2";
        let sig_der = Box::new(signer).sign(message).unwrap();

        // 解析 DER 签名并用底层 API 验签
        let sig_raw = sig_from_der(&sig_der).unwrap();
        verify_message(message, DEFAULT_ID, &pub_key, &sig_raw).unwrap();
    }
}
