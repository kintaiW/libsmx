//! SM2 验签 → rustls `SignatureVerificationAlgorithm`

use pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm};
use rustls::crypto::{SignatureScheme, WebPkiSupportedAlgorithms};

use crate::sm2::{der::sig_from_der, verify_message, DEFAULT_ID};

/// rustls 支持的 SM2_SM3 签名验证算法集合
pub static SUPPORTED_SM2_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&SM2_SM3_ALG],
    mapping: &[(SignatureScheme::SM2_SM3, &[&SM2_SM3_ALG])],
};

static SM2_SM3_ALG: Sm2Sm3Algorithm = Sm2Sm3Algorithm;

#[derive(Debug)]
struct Sm2Sm3Algorithm;

// SM2 OID: 1.2.156.10197.1.301 (encoded as DER OID bytes)
// SM2withSM3 SignatureAlgorithm OID: 1.2.156.10197.1.501
// AlgorithmIdentifier for SM2withSM3
const SM2SM3_OID: &[u8] = &[
    0x30, 0x0a, // SEQUENCE
    0x06, 0x08, // OID
    0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75, // 1.2.156.10197.1.501
];

impl SignatureVerificationAlgorithm for Sm2Sm3Algorithm {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        // id-ecPublicKey with SM2 curve parameter
        AlgorithmIdentifier::from_slice(&[
            0x30, 0x13, // SEQUENCE
            0x06, 0x07, // OID id-ecPublicKey
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, // OID SM2
            0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d,
        ])
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(SM2SM3_OID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), pki_types::InvalidSignature> {
        // 将 65 字节公钥转换为固定数组
        let pub_key_arr: &[u8; 65] = public_key
            .try_into()
            .map_err(|_| pki_types::InvalidSignature)?;

        // DER 解码签名
        let sig_raw = sig_from_der(signature).map_err(|_| pki_types::InvalidSignature)?;

        // SM2 验签（使用默认 ID，GB/T 32918.2）
        verify_message(message, DEFAULT_ID, pub_key_arr, &sig_raw)
            .map_err(|_| pki_types::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use pki_types::SignatureVerificationAlgorithm;

    use super::SM2_SM3_ALG;
    use crate::sm2::{der::sig_to_der, generate_keypair, sign_message, DEFAULT_ID};

    fn sign_with_der(message: &[u8]) -> ([u8; 65], Vec<u8>) {
        let mut rng = crate::rustls_provider::kx::Sm2Rng;
        let (pri_key, pub_key) = generate_keypair(&mut rng);
        let sig_raw = sign_message(message, DEFAULT_ID, &pri_key, &mut rng);
        (pub_key, sig_to_der(&sig_raw))
    }

    #[test]
    fn test_verify_valid_signature() {
        let msg = b"test message";
        let (pub_key, sig_der) = sign_with_der(msg);
        SM2_SM3_ALG
            .verify_signature(&pub_key, msg, &sig_der)
            .unwrap();
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (pub_key, sig_der) = sign_with_der(b"original");
        let result = SM2_SM3_ALG.verify_signature(&pub_key, b"tampered", &sig_der);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_pubkey_fails() {
        let msg = b"hello";
        let (_, sig_der) = sign_with_der(msg);
        // 用另一个公钥验证
        let mut rng = crate::rustls_provider::kx::Sm2Rng;
        let (_, other_pub) = generate_keypair(&mut rng);
        let result = SM2_SM3_ALG.verify_signature(&other_pub, msg, &sig_der);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_pubkey_len_fails() {
        let (_, sig_der) = sign_with_der(b"msg");
        // 公钥长度不是 65 字节时应报错
        let result = SM2_SM3_ALG.verify_signature(&[0u8; 32], b"msg", &sig_der);
        assert!(result.is_err());
    }
}
