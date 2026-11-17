//! rustls CryptoProvider 端到端集成测试（阶段 L.2）
//!
//! 使用 Raw Public Key（RFC 7250）模式，无需 X.509 证书，
//! 直接用 SM2 密钥对作为身份凭证完成 TLS 1.3 握手自回环测试。
//!
//! Reason: rustls 0.24 main 把连接改成外部缓冲（`Connection<Side, Tcp>`），
//!   旧的 `read_tls/write_tls/process_new_packets` 已移除，故测试驱动一并改写到新接口。

#![cfg(feature = "rustls-provider")]

use std::sync::Arc;

use pki_types::{PrivateSec1KeyDer, ServerName, SubjectPublicKeyInfoDer};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerIdentity, ServerVerifier, SignatureVerificationInput,
};
use rustls::client::ClientHandshake;
use rustls::crypto::{CipherSuite, CryptoProvider, SignatureScheme, VerifiedIdentity};
use rustls::enums::CertificateType;
use rustls::{
    ClientConfig, ClientSide, Connection, ServerConfig, ServerSide, SliceInput, Tcp,
};

use libsmx::rustls_provider;
use libsmx::sm2::{
    der::{public_key_to_spki_der, sig_from_der},
    generate_keypair, verify_message, DEFAULT_ID,
};

type ClientConn = Connection<ClientSide, Tcp>;
type ServerConn = Connection<ServerSide, Tcp>;

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

/// 把 client → server 方向的缓冲喂给服务端，完成握手消息或收下应用数据
fn server_read(
    server: &mut ServerConn,
    input: &mut Vec<u8>,
    output: &mut Vec<u8>,
    received: &mut Vec<u8>,
) {
    if input.is_empty() {
        return;
    }
    let mut slice = SliceInput::new(input);
    server
        .read_tls(&mut slice, output)
        .handle_all(received)
        .unwrap();
    let used = slice.into_used();
    input.drain(..used);
}

/// 让客户端状态机消费 server → client 方向的缓冲，必要时调用配置好的 verifier
fn client_process(
    state: ClientHandshake,
    input: &mut Vec<u8>,
    output: &mut Vec<u8>,
) -> ClientHandshake {
    let mut slice = SliceInput::new(input);
    let next = match state {
        ClientHandshake::NeedsInput(needs_input) => needs_input.process(&mut slice, output),
        ClientHandshake::VerifyServerIdentity(verify) => verify.with_config(output),
        other => return other,
    }
    .unwrap();
    let used = slice.into_used();
    input.drain(..used);
    next
}

/// 驱动完整 TLS 握手，返回完成后的客户端连接
fn do_handshake(
    mut client: ClientHandshake,
    server: &mut ServerConn,
    c2s: &mut Vec<u8>,
    s2c: &mut Vec<u8>,
) -> ClientConn {
    loop {
        server_read(server, c2s, s2c, &mut Vec::new());
        if let ClientHandshake::Complete(conn) = client {
            // Reason: 客户端完成后还要把 Finished 交给服务端，握手才算双向闭合。
            assert!(!server.is_handshaking());
            return conn;
        }
        assert!(!s2c.is_empty(), "handshake stalled");
        client = client_process(client, s2c, c2s);
    }
}

/// client → server 方向投喂应用数据，并把明文收进 `received`
fn deliver_to_server(
    client: &mut ClientConn,
    server: &mut ServerConn,
    msg: &[u8],
    c2s: &mut Vec<u8>,
    s2c: &mut Vec<u8>,
) -> Vec<u8> {
    client.write(msg.into(), c2s).unwrap();
    let mut received = Vec::new();
    server_read(server, c2s, s2c, &mut received);
    received
}

/// server → client 方向投喂应用数据，并把明文收进 `received`
fn deliver_to_client(
    server: &mut ServerConn,
    client: &mut ClientConn,
    msg: &[u8],
    c2s: &mut Vec<u8>,
    s2c: &mut Vec<u8>,
) -> Vec<u8> {
    server.write(msg.into(), s2c).unwrap();
    let mut received = Vec::new();
    {
        let mut slice = SliceInput::new(s2c);
        client
            .read_tls(&mut slice, c2s)
            .handle_all(&mut received)
            .unwrap();
        let used = slice.into_used();
        s2c.drain(..used);
    }
    received
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
    fn verify_identity<'a>(
        &self,
        identity: &ServerIdentity<'a, '_>,
    ) -> Result<VerifiedIdentity<'a>, rustls::Error> {
        // Reason: 测试中不验证服务端身份（Raw Public Key 模式，无 CA 信任链），
        //   直接把呈现的身份标记为已验证。
        Ok(VerifiedIdentity::assertion(identity.identity.clone()))
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
    let server_config = ServerConfig::builder(Arc::new(provider.clone()))
        .with_no_client_auth()
        .with_server_credential_resolver(cert_resolver)
        .unwrap();

    // 客户端：自定义 verifier 跳过证书链校验
    let verifier = Arc::new(AcceptAllSm2ServerVerifier::new());
    let client_config = ClientConfig::builder(Arc::new(provider.clone()))
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
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    let client = ClientHandshake::NeedsInput(
        Arc::new(client_config)
            .connect(server_name)
            .start_handshake(&mut c2s)
            .unwrap(),
    );
    let mut server: ServerConn = Connection::new(Arc::new(server_config)).unwrap();
    let mut client = do_handshake(client, &mut server, &mut c2s, &mut s2c);

    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS13_SM4_GCM_SM3,
    );

    // server → client 数据传输
    let plaintext = b"Hello, SM2/SM4/SM3!";
    let received = deliver_to_client(&mut server, &mut client, plaintext, &mut c2s, &mut s2c);
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
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    let client = ClientHandshake::NeedsInput(
        Arc::new(client_config)
            .connect(server_name)
            .start_handshake(&mut c2s)
            .unwrap(),
    );
    let mut server: ServerConn = Connection::new(Arc::new(server_config)).unwrap();
    let mut client = do_handshake(client, &mut server, &mut c2s, &mut s2c);

    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS13_SM4_CCM_SM3,
    );

    // client → server 数据传输
    let msg = b"SM4-CCM test";
    let received = deliver_to_server(&mut client, &mut server, msg, &mut c2s, &mut s2c);
    assert_eq!(received, msg.to_vec());
}

/// 验证握手后密钥交换组为 curveSM2
#[test]
fn test_kx_group_is_curve_sm2() {
    let provider = rustls_provider::provider();
    let (server_sec1, server_spki) = make_sm2_keypair();
    let (server_config, client_config) = make_configs(&provider, server_sec1, server_spki);

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    let client = ClientHandshake::NeedsInput(
        Arc::new(client_config)
            .connect(server_name)
            .start_handshake(&mut c2s)
            .unwrap(),
    );
    let mut server: ServerConn = Connection::new(Arc::new(server_config)).unwrap();
    let client = do_handshake(client, &mut server, &mut c2s, &mut s2c);

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
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    let client = ClientHandshake::NeedsInput(
        Arc::new(client_config)
            .connect(server_name)
            .start_handshake(&mut c2s)
            .unwrap(),
    );
    let mut server: ServerConn = Connection::new(Arc::new(server_config)).unwrap();
    let mut client = do_handshake(client, &mut server, &mut c2s, &mut s2c);

    // client → server
    let c2s_msg = b"from client";
    let received = deliver_to_server(&mut client, &mut server, c2s_msg, &mut c2s, &mut s2c);
    assert_eq!(received, c2s_msg.to_vec());

    // server → client
    let s2c_msg = b"from server";
    let received = deliver_to_client(&mut server, &mut client, s2c_msg, &mut c2s, &mut s2c);
    assert_eq!(received, s2c_msg.to_vec());
}
