//! SM2 签名与密钥 DER 编解码
//!
//! ## 签名格式
//! TLS 使用 ASN.1 DER 格式表示签名：
//! ```text
//! SEQUENCE {
//!     INTEGER r,
//!     INTEGER s
//! }
//! ```
//! 而 libsmx 内部使用原始 `r||s`（64 字节）。本模块提供两者互转。
//!
//! ## 私钥格式
//! - **SEC1**（RFC 5915）：`ECPrivateKey SEQUENCE { version INTEGER(1), privateKey OCTET STRING, ... }`
//! - **PKCS#8**（RFC 5958）：`PrivateKeyInfo SEQUENCE { version INTEGER(0), algorithm, privateKey OCTET STRING(SEC1) }`
//!
//! ## DER INTEGER 编码规则
//! - 去除前导零（但若最高位为 1，需在前补 0x00 防止被解析为负数）
//! - tag = 0x02，length 占 1 字节（r/s < 256 位时长度 ≤ 33）
//! - SEQUENCE tag = 0x30

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Error;
use crate::sm2::PrivateKey;

/// 将原始签名 `r||s`（64 字节）编码为 DER SEQUENCE
///
/// 输出格式：`30 <len> 02 <rlen> <r> 02 <slen> <s>`
#[cfg(feature = "alloc")]
pub fn sig_to_der(raw: &[u8; 64]) -> Vec<u8> {
    let r = &raw[..32];
    let s = &raw[32..];

    let r_enc = encode_integer(r);
    let s_enc = encode_integer(s);

    let inner_len = r_enc.len() + s_enc.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30); // SEQUENCE tag
    der.push(inner_len as u8); // SEQUENCE length（inner < 256 字节）
    der.extend_from_slice(&r_enc);
    der.extend_from_slice(&s_enc);
    der
}

/// 将 DER 编码签名解码为原始 `r||s`（64 字节）
///
/// # 错误
/// 格式不合法时返回 `Error::InvalidSignature`
pub fn sig_from_der(der: &[u8]) -> Result<[u8; 64], Error> {
    let err = || Error::InvalidSignature;

    // SEQUENCE tag
    let (tag, rest) = split_first(der).ok_or_else(err)?;
    if *tag != 0x30 {
        return Err(err());
    }

    // SEQUENCE length
    let (seq_len, rest) = split_first(rest).ok_or_else(err)?;
    let seq_len = *seq_len as usize;
    if rest.len() < seq_len {
        return Err(err());
    }
    let body = &rest[..seq_len];

    // 解析 r
    let (r_bytes, body) = decode_integer(body).ok_or_else(err)?;

    // 解析 s
    let (s_bytes, body) = decode_integer(body).ok_or_else(err)?;

    // 不应有多余数据
    if !body.is_empty() {
        return Err(err());
    }

    // r 和 s 都必须是正整数，不超过 32 字节
    if r_bytes.is_empty() || r_bytes.len() > 33 || s_bytes.is_empty() || s_bytes.len() > 33 {
        return Err(err());
    }

    let mut raw = [0u8; 64];
    // Reason: DER INTEGER 可能有前缀 0x00（最高位保护），去除后左对齐写入 32 字节槽
    let r_stripped = strip_leading_zero(r_bytes);
    let s_stripped = strip_leading_zero(s_bytes);
    if r_stripped.len() > 32 || s_stripped.len() > 32 {
        return Err(err());
    }
    let r_off = 32 - r_stripped.len();
    let s_off = 32 - s_stripped.len();
    raw[r_off..32].copy_from_slice(r_stripped);
    raw[32 + s_off..64].copy_from_slice(s_stripped);

    Ok(raw)
}

// ── 内部辅助 ──────────────────────────────────────────────────────────────────

/// 将 32 字节大端整数编码为 DER INTEGER（带 tag 0x02 和 length）
#[cfg(feature = "alloc")]
fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    // 去除前导零（至少保留 1 字节）
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let val = &bytes[start..];

    // 最高位为 1 时需补 0x00，防止被解析为负数
    let needs_pad = val[0] & 0x80 != 0;
    let val_len = val.len() + if needs_pad { 1 } else { 0 };

    let mut enc = Vec::with_capacity(2 + val_len);
    enc.push(0x02); // INTEGER tag
    enc.push(val_len as u8); // length
    if needs_pad {
        enc.push(0x00);
    }
    enc.extend_from_slice(val);
    enc
}

/// 从字节流中解析一个 DER INTEGER，返回 (value_bytes, 剩余字节)
fn decode_integer(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, rest) = split_first(data)?;
    if *tag != 0x02 {
        return None;
    }
    let (len, rest) = split_first(rest)?;
    let len = *len as usize;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

/// 去除前导 0x00 字节
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => &bytes[bytes.len().saturating_sub(1)..], // 全零时保留末字节
    }
}

fn split_first(data: &[u8]) -> Option<(&u8, &[u8])> {
    data.split_first()
}

// ── DER 长度解码 ──────────────────────────────────────────────────────────────

/// 解析 DER 长度字段，返回 (length, 剩余字节)
///
/// 支持：单字节（< 0x80）、两字节（0x81 nn）、三字节（0x82 nn nn）
fn parse_length(data: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = data.split_first()?;
    if *first < 0x80 {
        // Reason: 最高位为 0 时，本字节直接表示长度
        Some((*first as usize, rest))
    } else if *first == 0x81 {
        let (len, rest) = rest.split_first()?;
        Some((*len as usize, rest))
    } else if *first == 0x82 {
        if rest.len() < 2 {
            return None;
        }
        let len = (rest[0] as usize) << 8 | rest[1] as usize;
        Some((len, &rest[2..]))
    } else {
        // 不支持更长或不定长编码
        None
    }
}

/// 解析一个 TLV（tag-length-value），返回 (value_bytes, 剩余字节)
fn parse_tlv(data: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (tag, rest) = data.split_first()?;
    if *tag != expected_tag {
        return None;
    }
    let (len, rest) = parse_length(rest)?;
    if rest.len() < len {
        return None;
    }
    Some((&rest[..len], &rest[len..]))
}

// ── 私钥 DER 解析 ─────────────────────────────────────────────────────────────

/// 从 SEC1 DER 解析 SM2 私钥（RFC 5915）
///
/// 格式：
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///     version    INTEGER { ecPrivkeyVer1(1) },
///     privateKey OCTET STRING,          -- 32 字节原始私钥
///     [0] ECParameters OPTIONAL,
///     [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// # 错误
/// DER 格式不合法或私钥范围不合法时返回 `Error::InvalidPrivateKey`
pub fn private_key_from_sec1_der(der: &[u8]) -> Result<PrivateKey, Error> {
    let err = || Error::InvalidPrivateKey;

    // 解析外层 SEQUENCE
    let (seq_body, _) = parse_tlv(der, 0x30).ok_or_else(err)?;

    // version INTEGER，值应为 1（ecPrivkeyVer1）
    let (ver_bytes, rest) = parse_tlv(seq_body, 0x02).ok_or_else(err)?;
    if ver_bytes != [0x01] {
        return Err(err());
    }

    // privateKey OCTET STRING（32 字节）
    let (key_bytes, _rest) = parse_tlv(rest, 0x04).ok_or_else(err)?;
    if key_bytes.len() != 32 {
        return Err(err());
    }
    let key_arr: &[u8; 32] = key_bytes.try_into().map_err(|_| err())?;

    PrivateKey::from_bytes(key_arr)
}

/// 从 PKCS#8 DER 解析 SM2 私钥（RFC 5958）
///
/// 格式：
/// ```text
/// PrivateKeyInfo ::= SEQUENCE {
///     version              INTEGER (0),
///     algorithm            AlgorithmIdentifier SEQUENCE { ... },
///     privateKey           OCTET STRING (SEC1 DER)
/// }
/// ```
///
/// # 错误
/// DER 格式不合法或私钥范围不合法时返回 `Error::InvalidPrivateKey`
pub fn private_key_from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
    let err = || Error::InvalidPrivateKey;

    // 解析外层 SEQUENCE（PrivateKeyInfo）
    let (seq_body, _) = parse_tlv(der, 0x30).ok_or_else(err)?;

    // version INTEGER，值应为 0
    let (ver_bytes, rest) = parse_tlv(seq_body, 0x02).ok_or_else(err)?;
    if ver_bytes != [0x00] {
        return Err(err());
    }

    // AlgorithmIdentifier SEQUENCE（跳过，不验证 OID）
    let (_, rest) = parse_tlv(rest, 0x30).ok_or_else(err)?;

    // privateKey OCTET STRING（内含 SEC1 DER）
    let (sec1_der, _) = parse_tlv(rest, 0x04).ok_or_else(err)?;

    private_key_from_sec1_der(sec1_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(r: [u8; 32], s: [u8; 32]) -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);
        raw
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_basic() {
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_high_bit_set() {
        // r/s 最高位为 1，需要 DER 填充 0x00
        let mut r = [0u8; 32];
        r[0] = 0x80; // 最高位为 1
        let mut s = [0u8; 32];
        s[0] = 0xFF;
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        // 验证 DER 中有 0x00 填充
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_roundtrip_leading_zeros() {
        // r 前有大量前导零
        let mut r = [0u8; 32];
        r[31] = 0x42; // 只有最后一字节非零
        let s = [0x01u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        let recovered = sig_from_der(&der).unwrap();
        assert_eq!(recovered, raw);
    }

    #[test]
    fn test_der_invalid_tag() {
        // 非 SEQUENCE tag
        let bad = [0x10, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert!(sig_from_der(&bad).is_err());
    }

    #[test]
    fn test_der_truncated() {
        let bad = [0x30, 0x10]; // length 声明 16 字节但无内容
        assert!(sig_from_der(&bad).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_der_structure() {
        // 验证 DER 字节结构符合 ASN.1 规范
        let r = [0x01u8; 32];
        let s = [0x01u8; 32];
        let raw = make_raw(r, s);
        let der = sig_to_der(&raw);
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[2], 0x02); // INTEGER tag for r
                                  // 长度字段合理（r/s 各最多 33 字节 + 2 字节头 = 35，×2 + 2 = 72）
        assert!(der.len() <= 72);
        assert!(der.len() >= 8);
    }

    // ── 私钥 DER 解析测试 ──────────────────────────────────────────────────────

    // 已知 SM2 私钥原始字节（与其他测试共用）
    const RAW_KEY: [u8; 32] = [
        0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f,
        0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7,
        0xc5, 0xb8,
    ];

    /// 构造最小 SEC1 DER（只有 version + privateKey 字段）
    #[cfg(feature = "alloc")]
    fn make_sec1_der(key: &[u8; 32]) -> alloc::vec::Vec<u8> {
        // version INTEGER = 1：02 01 01
        // privateKey OCTET STRING：04 20 <32 bytes>
        // inner = 3 + 2 + 32 = 37 bytes → SEQUENCE 30 25 ...
        let mut der = alloc::vec![0x30u8, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
        der.extend_from_slice(key);
        der
    }

    /// 构造最小 PKCS#8 DER（包含虚拟 AlgorithmIdentifier OID）
    #[cfg(feature = "alloc")]
    fn make_pkcs8_der(key: &[u8; 32]) -> alloc::vec::Vec<u8> {
        let sec1 = make_sec1_der(key);
        // AlgorithmIdentifier 最小化：30 06 06 01 00 06 01 00（两个 OID，各 1 字节占位）
        let alg_id: &[u8] = &[0x30, 0x06, 0x06, 0x01, 0x00, 0x06, 0x01, 0x00];
        // version INTEGER = 0：02 01 00
        let version: &[u8] = &[0x02, 0x01, 0x00];
        // privateKey OCTET STRING 包装 sec1
        let mut priv_oct = alloc::vec![0x04u8, sec1.len() as u8];
        priv_oct.extend_from_slice(&sec1);
        // inner = version + alg_id + priv_oct
        let inner_len = version.len() + alg_id.len() + priv_oct.len();
        let mut der = alloc::vec![0x30u8, inner_len as u8];
        der.extend_from_slice(version);
        der.extend_from_slice(alg_id);
        der.extend_from_slice(&priv_oct);
        der
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_sec1_der_roundtrip() {
        let der = make_sec1_der(&RAW_KEY);
        let key = private_key_from_sec1_der(&der).expect("SEC1 解析应成功");
        assert_eq!(key.as_bytes(), &RAW_KEY);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pkcs8_der_roundtrip() {
        let der = make_pkcs8_der(&RAW_KEY);
        let key = private_key_from_pkcs8_der(&der).expect("PKCS#8 解析应成功");
        assert_eq!(key.as_bytes(), &RAW_KEY);
    }

    #[test]
    fn test_sec1_der_invalid_tag() {
        // 首字节不是 SEQUENCE tag
        let bad = [0x02u8, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 0x00];
        assert!(private_key_from_sec1_der(&bad).is_err());
    }

    #[test]
    fn test_sec1_der_wrong_version() {
        // version 应为 1，此处给 0；最后 32 字节填充为 RAW_KEY
        let mut der = [0u8; 39];
        der[0] = 0x30;
        der[1] = 0x25; // SEQUENCE length 37
        der[2] = 0x02;
        der[3] = 0x01;
        der[4] = 0x00; // version = 0（错误，应为 1）
        der[5] = 0x04;
        der[6] = 0x20; // OCTET STRING 32 字节
        der[7..39].copy_from_slice(&RAW_KEY);
        assert!(private_key_from_sec1_der(&der).is_err());
    }

    #[test]
    fn test_sec1_der_key_too_short() {
        // privateKey 只有 16 字节（不足 32）
        let der = [
            0x30, 0x15, // SEQUENCE 21 字节
            0x02, 0x01, 0x01, // version = 1
            0x04, 0x10, // OCTET STRING 16 字节
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(private_key_from_sec1_der(&der).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_pkcs8_der_invalid_outer_tag() {
        let mut der = make_pkcs8_der(&RAW_KEY);
        der[0] = 0x04; // 破坏外层 SEQUENCE tag
        assert!(private_key_from_pkcs8_der(&der).is_err());
    }
}
