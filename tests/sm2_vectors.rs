//! SM2 集成测试（往返验证 + 边界测试）
//!
//! 注：GB/T 32918.2-2016 附录 A 的精确测试向量需要从官方标准文档获取。
//! 此文件提供功能完整性验证测试。

use crypto_bigint::U256;
use libsmx::sm2::{get_e, get_z, sign_with_k, verify, PrivateKey};

/// 使用标准附录 A 私钥和随机数进行签名，然后验签（往返测试）
///
/// 私钥 d 来自 GB/T 32918.2-2016 附录 A.2 示例
#[test]
fn test_sm2_sign_verify_with_known_key() {
    // GB/T 32918.2-2016 附录 A 私钥
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")
            .unwrap();
    let k_bytes =
        hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21")
            .unwrap();

    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap())
        .expect("私钥应有效");
    let pub_key = pri_key.public_key();

    let id = b"ALICE123@YAHOO.COM";
    let msg = b"message digest";

    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(&k_bytes);
    let sig = sign_with_k(&e, &pri_key, &k).expect("签名应成功");

    // 验签
    verify(&e, &pub_key, &sig).expect("验签应成功");

    // 签名长度正确
    assert_eq!(sig.len(), 64, "签名应为 64 字节");
}

/// 不同消息产生不同签名（同一 k）
#[test]
fn test_sm2_different_messages_different_sigs() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")
            .unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"test_user";
    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21")
            .unwrap(),
    );

    let z = get_z(id, &pub_key);
    let e1 = get_e(&z, b"message 1");
    let e2 = get_e(&z, b"message 2");

    let sig1 = sign_with_k(&e1, &pri_key, &k).unwrap();
    let sig2 = sign_with_k(&e2, &pri_key, &k).unwrap();

    // 不同消息签名结果不同（r 相同因为 k 相同，但 s 不同）
    assert_ne!(sig1[32..], sig2[32..], "不同消息的 s 值应不同");
}

/// 验签对篡改消息应失败
#[test]
fn test_sm2_verify_tampered_message_fails() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")
            .unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"1234567812345678";
    let msg = b"original message";
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21")
            .unwrap(),
    );
    let sig = sign_with_k(&e, &pri_key, &k).unwrap();

    // 对不同消息的摘要验签，应失败
    let e_wrong = get_e(&z, b"tampered message");
    assert!(
        verify(&e_wrong, &pub_key, &sig).is_err(),
        "篡改消息后验签应失败"
    );
}

/// 验签对篡改签名应失败
#[test]
fn test_sm2_verify_tampered_sig_fails() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")
            .unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"1234567812345678";
    let msg = b"test message";
    let z = get_z(id, &pub_key);
    let e = get_e(&z, msg);

    let k = U256::from_be_slice(
        &hex::decode("59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21")
            .unwrap(),
    );
    let mut sig = sign_with_k(&e, &pri_key, &k).unwrap();
    sig[0] ^= 1; // 篡改 r 的第一字节

    assert!(
        verify(&e, &pub_key, &sig).is_err(),
        "篡改签名后验签应失败"
    );
}

/// Z 值计算确定性验证（相同输入产生相同 Z）
#[test]
fn test_sm2_z_value_deterministic() {
    let d_bytes =
        hex::decode("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8")
            .unwrap();
    let pri_key = PrivateKey::from_bytes(d_bytes.as_slice().try_into().unwrap()).unwrap();
    let pub_key = pri_key.public_key();

    let id = b"ALICE123@YAHOO.COM";
    let z1 = get_z(id, &pub_key);
    let z2 = get_z(id, &pub_key);
    assert_eq!(z1, z2, "Z 值计算应为确定性");
}
