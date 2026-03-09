//! rustls `CryptoProvider` 实现（RFC 8998 国密 TLS 套件）

extern crate alloc;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::sync::Arc;

use pki_types::PrivateKeyDer;
use rustls::crypto::{
    CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SigningKey, TicketProducer,
    TicketerFactory,
};
use rustls::error::Error;

pub mod hash;
pub mod hmac;
pub mod kx;
pub mod sign;
pub mod tls13;
pub mod verify;

/// 构造国密 `CryptoProvider`
pub fn provider() -> CryptoProvider {
    static TLS13_SUITES: &[&rustls::Tls13CipherSuite] =
        &[tls13::TLS13_SM4_GCM_SM3, tls13::TLS13_SM4_CCM_SM3];
    static KX_GROUPS: &[&dyn rustls::crypto::kx::SupportedKxGroup] = &[kx::CURVE_SM2];

    CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(&[]),
        tls13_cipher_suites: Cow::Borrowed(TLS13_SUITES),
        kx_groups: Cow::Borrowed(KX_GROUPS),
        signature_verification_algorithms: verify::SUPPORTED_SM2_ALGS,
        secure_random: &Random,
        key_provider: &SmKeyProvider,
        ticketer_factory: &SmTicketerFactory,
    }
}

// ── SecureRandom ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::getrandom(buf).map_err(|_| GetRandomFailed)
    }
}

// ── KeyProvider ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SmKeyProvider;

impl KeyProvider for SmKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        sign::load_private_key(key_der)
    }
}

// ── TicketerFactory ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct SmTicketerFactory;

impl TicketerFactory for SmTicketerFactory {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        // Reason: TLS session ticket 加密暂不支持，返回错误；
        //   后续可用 SM4-GCM 实现 ticket 加密
        Err(Error::General("SM ticket factory not yet implemented".into()))
    }
}
