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
        PrivateKeyDer::Sec1(sec1) => crate::sm2::der::private_key_from_sec1_der(sec1.secret_sec1_der())
            .map_err(|_| Error::General("invalid SEC1 SM2 private key".into()))?,
        PrivateKeyDer::Pkcs8(pkcs8) => crate::sm2::der::private_key_from_pkcs8_der(pkcs8.secret_pkcs8_der())
            .map_err(|_| Error::General("invalid PKCS#8 SM2 private key".into()))?,
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
