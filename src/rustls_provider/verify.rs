//! SM2 验签 → rustls `SignatureVerificationAlgorithm`

use pki_types::{AlgorithmIdentifier, SignatureVerificationAlgorithm};
use rustls::crypto::{WebPkiSupportedAlgorithms, SignatureScheme};

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
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, // OID SM2
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
        let sig_raw =
            sig_from_der(signature).map_err(|_| pki_types::InvalidSignature)?;

        // SM2 验签（使用默认 ID，GB/T 32918.2）
        verify_message(message, DEFAULT_ID, pub_key_arr, &sig_raw)
            .map_err(|_| pki_types::InvalidSignature)
    }
}
