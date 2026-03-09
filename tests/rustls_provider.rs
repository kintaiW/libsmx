//! rustls CryptoProvider 端到端集成测试（阶段 L.2）
//!
//! 使用 Raw Public Key（RFC 7250）模式，无需 X.509 证书，
//! 直接用 SM2 密钥对作为身份凭证完成 TLS 1.3 握手自回环测试。

#![cfg(feature = "rustls-provider")]

use std::io::{Read, Write};
use std::sync::Arc;

use pki_types::{PrivateSec1KeyDer, ServerName, SubjectPublicKeyInfoDer};
use rustls::client::danger::{
    HandshakeSignatureValid, PeerVerified, ServerIdentity, ServerVerifier,
};
use rustls::crypto::{CipherSuite, CryptoProvider, SignatureScheme};
use rustls::enums::CertificateType;
use rustls::server::danger::SignatureVerificationInput;
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

use libsmx::rustls_provider;
use libsmx::sm2::{
    der::{public_key_to_spki_der, sig_from_der},
    generate_keypair, verify_message, DEFAULT_ID,
};

// ── 测试用 RNG ────────────────────────────────────────────────────────────────

struct TestRng;

impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).unwrap();
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        getrandom::getrandom(&mut b).unwrap();
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).unwrap();
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|_| {
            use core::num::NonZeroU32;
            rand_core::Error::from(NonZeroU32::new(1).unwrap())
        })
    }
}

// ── 测试工具 ──────────────────────────────────────────────────────────────────

/// 生成 SM2 密钥对，返回 (SEC1 DER 私钥, SPKI DER 公钥)
fn make_sm2_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = TestRng;
    let (pri_key, pub_key) = generate_keypair(&mut rng);

    // 最小 SEC1 DER: SEQUENCE { INTEGER(1), OCTET STRING(32B) }
    let mut sec1 = Vec::with_capacity(39);
    sec1.extend_from_slice(&[
        0x30, 0x25, // SEQUENCE, length 37
        0x02, 0x01, 0x01, // INTEGER(1) version
        0x04, 0x20, // OCTET STRING, length 32
    ]);
    sec1.extend_from_slice(pri_key.as_bytes());

    let spki = public_key_to_spki_der(&pub_key);
    (sec1, spki)
}

/// 在内存中传输 TLS 记录（left → right）
fn transfer(left: &mut impl Connection, right: &mut impl Connection) -> usize {
    let mut buf = [0u8; 65536];
    let mut total = 0;
    while left.wants_write() {
        let n = left.write_tls(&mut &mut buf[..]).unwrap();
        if n == 0 {
            break;
        }
        total += n;
        let mut offs = 0;
        while offs < n {
            offs += right.read_tls(&mut &buf[offs..n]).unwrap();
        }
    }
    total
}

/// 驱动完整 TLS 握手
fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    while client.is_handshaking() || server.is_handshaking() {
        transfer(client, server);
        server.process_new_packets().unwrap();
        transfer(server, client);
        client.process_new_packets().unwrap();
    }
}

// ── 自定义 ServerVerifier（测试用，接受任意 SM2 Raw Public Key）──────────────

#[derive(Debug)]
struct AcceptAllSm2ServerVerifier;

impl AcceptAllSm2ServerVerifier {
    fn new() -> Self {
        Self
    }
}

impl ServerVerifier for AcceptAllSm2ServerVerifier {
    fn verify_identity(
        &self,
        _identity: &ServerIdentity<'_>,
    ) -> Result<PeerVerified, rustls::Error> {
        // Reason: 测试中不验证服务端身份（Raw Public Key 模式，无 CA 信任链）
        Ok(PeerVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        input: &SignatureVerificationInput<'_>,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Reason: webpki 不支持 SM2 OID，直接调用 libsmx SM2 验签实现，
        //   绕过 webpki 的 OID 匹配逻辑
        use rustls::SignerPublicKey;
        let spki_der: &[u8] = match input.signer {
            SignerPublicKey::RawPublicKey(spki) => spki.as_ref(),
            _ => return Err(rustls::Error::General("expected Raw Public Key".into())),
        };
        // SM2 SPKI 结构（91字节）：
        //   SEQUENCE(2B) + AlgId SEQUENCE(21B) + BIT STRING tag+len+pad(3B) + 公钥(65B)
        //   公钥从偏移 26 开始，共 65 字节
        if spki_der.len() != 91 {
            return Err(rustls::Error::General(format!(
                "unexpected SPKI length: {}",
                spki_der.len()
            )));
        }
        let pub_key_bytes: &[u8; 65] = spki_der[26..91]
            .try_into()
            .map_err(|_| rustls::Error::General("bad pubkey slice".into()))?;

        let sig_der = input.signature.signature();
        let sig_raw = sig_from_der(sig_der)
            .map_err(|_| rustls::Error::General("invalid DER signature".into()))?;

        verify_message(input.message, DEFAULT_ID, pub_key_bytes, &sig_raw)
            .map(|_| HandshakeSignatureValid::assertion())
            .map_err(|_| rustls::Error::General("SM2 signature verification failed".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::SM2_SM3]
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::RawPublicKey]
    }

    fn hash_config(&self, _: &mut dyn core::hash::Hasher) {}
}

// ── 辅助：用 Raw Public Key 模式构建 server/client Config ────────────────────

fn make_configs(
    provider: &CryptoProvider,
    server_sec1: Vec<u8>,
    server_spki: Vec<u8>,
) -> (ServerConfig, ClientConfig) {
    // 服务端：用 new_unchecked 绕过 webpki 对 SM2 OID 的校验
    let server_key_der = pki_types::PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(server_sec1));
    let server_signing_key = provider
        .key_provider
        .load_private_key(server_key_der)
        .unwrap();
    let identity = Arc::new(rustls::crypto::Identity::RawPublicKey(
        SubjectPublicKeyInfoDer::from(server_spki),
    ));
    // Reason: Credentials::new_unchecked 跳过 webpki 验证，因为 SM2 OID 尚未被
    //   rustls-webpki 支持，但我们的 SignatureVerificationAlgorithm 实现是正确的
    let creds = rustls::crypto::Credentials::new_unchecked(identity, server_signing_key);
    let cert_resolver = Arc::new(rustls::crypto::SingleCredential::from(creds));
    let server_config = ServerConfig::builder(provider.clone().into())
        .with_no_client_auth()
        .with_server_credential_resolver(cert_resolver)
        .unwrap();

    // 客户端：自定义 verifier 跳过证书链校验
    let verifier = Arc::new(AcceptAllSm2ServerVerifier::new());
    let client_config = ClientConfig::builder(provider.clone().into())
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
        .unwrap();

    (server_config, client_config)
}

// ── 测试用例 ──────────────────────────────────────────────────────────────────

/// TLS 1.3 SM4-GCM-SM3 握手自回环（Raw Public Key 模式）
#[test]
fn test_tls13_sm4_gcm_sm3_handshake() {
    let provider = rustls_provider::provider();
    let (server_sec1, server_spki) = make_sm2_keypair();
    let (server_config, client_config) = make_configs(&provider, server_sec1, server_spki);

    let server_name = ServerName::try_from("localhost").unwrap();
    let client_arc = Arc::new(client_config);
    let mut client = client_arc.connect(server_name).build().unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    do_handshake(&mut client, &mut server);

    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS13_SM4_GCM_SM3,
    );

    // server → client 数据传输
    let plaintext = b"Hello, SM2/SM4/SM3!";
    server.writer().write_all(plaintext).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let mut received = vec![0u8; plaintext.len()];
    client.reader().read_exact(&mut received).unwrap();
    assert_eq!(received, plaintext.to_vec());
}

/// TLS 1.3 SM4-CCM-SM3 握手自回环
#[test]
fn test_tls13_sm4_ccm_sm3_handshake() {
    use std::borrow::Cow;

    static CCM_SUITES: &[&rustls::Tls13CipherSuite] =
        &[libsmx::rustls_provider::tls13::TLS13_SM4_CCM_SM3];

    let provider = CryptoProvider {
        tls13_cipher_suites: Cow::Borrowed(CCM_SUITES),
        ..rustls_provider::provider()
    };

    let (server_sec1, server_spki) = make_sm2_keypair();
    let (server_config, client_config) = make_configs(&provider, server_sec1, server_spki);

    let server_name = ServerName::try_from("localhost").unwrap();
    let client_arc = Arc::new(client_config);
    let mut client = client_arc.connect(server_name).build().unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    do_handshake(&mut client, &mut server);

    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS13_SM4_CCM_SM3,
    );

    // client → server 数据传输
    let msg = b"SM4-CCM test";
    client.writer().write_all(msg).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut buf = vec![0u8; msg.len()];
    server.reader().read_exact(&mut buf).unwrap();
    assert_eq!(buf, msg.to_vec());
}

/// 验证握手后密钥交换组为 curveSM2
#[test]
fn test_kx_group_is_curve_sm2() {
    let provider = rustls_provider::provider();
    let (server_sec1, server_spki) = make_sm2_keypair();
    let (server_config, client_config) = make_configs(&provider, server_sec1, server_spki);

    let server_name = ServerName::try_from("localhost").unwrap();
    let client_arc = Arc::new(client_config);
    let mut client = client_arc.connect(server_name).build().unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    do_handshake(&mut client, &mut server);

    assert_eq!(
        client
            .negotiated_key_exchange_group()
            .map(|g: &dyn rustls::crypto::kx::SupportedKxGroup| g.name()),
        Some(rustls::crypto::kx::NamedGroup::curveSM2),
    );
}

/// 双向数据传输（client ↔ server 各发一条消息）
#[test]
fn test_bidirectional_data_transfer() {
    let provider = rustls_provider::provider();
    let (server_sec1, server_spki) = make_sm2_keypair();
    let (server_config, client_config) = make_configs(&provider, server_sec1, server_spki);

    let server_name = ServerName::try_from("localhost").unwrap();
    let client_arc = Arc::new(client_config);
    let mut client = client_arc.connect(server_name).build().unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    do_handshake(&mut client, &mut server);

    // client → server
    let c2s = b"from client";
    client.writer().write_all(c2s).unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    let mut buf = vec![0u8; c2s.len()];
    server.reader().read_exact(&mut buf).unwrap();
    assert_eq!(buf, c2s.to_vec());

    // server → client
    let s2c = b"from server";
    server.writer().write_all(s2c).unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    let mut buf2 = vec![0u8; s2c.len()];
    client.reader().read_exact(&mut buf2).unwrap();
    assert_eq!(buf2, s2c.to_vec());
}
