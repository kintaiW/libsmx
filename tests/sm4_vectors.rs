//! SM4 国标测试向量（GB/T 32907-2016 附录 A）
//!
//! A.1 示例1：单次 ECB 加密
//! A.2 示例2：1,000,000 次迭代 ECB 加密（验证算法迭代正确性）

use libsmx::sm4::{sm4_decrypt_ecb, sm4_encrypt_ecb};

/// GB/T 32907-2016 附录 A.1
/// 密钥：0123456789abcdeffedcba9876543210
/// 明文：0123456789abcdeffedcba9876543210
/// 密文：681edf34d206965e86b3e94f536e4246
#[test]
fn test_sm4_ecb_vector_a1_single() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let plaintext = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let expected_ct = hex::decode("681edf34d206965e86b3e94f536e4246").unwrap();

    let key_arr: [u8; 16] = key.try_into().unwrap();
    let ct = sm4_encrypt_ecb(&key_arr, &plaintext);
    assert_eq!(ct, expected_ct, "GB/T 32907 附录 A.1 加密失败");

    let pt = sm4_decrypt_ecb(&key_arr, &ct);
    assert_eq!(pt, plaintext, "GB/T 32907 附录 A.1 解密失败");
}

/// GB/T 32907-2016 附录 A.2
/// 密钥：0123456789abcdeffedcba9876543210
/// 明文：0123456789abcdeffedcba9876543210（反复迭代 1,000,000 次）
/// 密文：595298c7c6fd271f0402f804c33d3f66
#[test]
fn test_sm4_ecb_vector_a2_million_iterations() {
    let key: [u8; 16] = hex::decode("0123456789abcdeffedcba9876543210")
        .unwrap()
        .try_into()
        .unwrap();

    let mut data: Vec<u8> = hex::decode("0123456789abcdeffedcba9876543210").unwrap();

    for _ in 0..1_000_000 {
        data = sm4_encrypt_ecb(&key, &data);
    }

    let expected = hex::decode("595298c7c6fd271f0402f804c33d3f66").unwrap();
    assert_eq!(data, expected, "GB/T 32907 附录 A.2 百万次迭代失败");
}

/// ECB 解密是加密的逆操作（往返测试）
#[test]
fn test_sm4_ecb_roundtrip() {
    let key = [0x01u8; 16];
    let plaintext = b"SM4 ECB test!!!\x00";
    let ct = sm4_encrypt_ecb(&key, plaintext);
    let pt = sm4_decrypt_ecb(&key, &ct);
    assert_eq!(pt.as_slice(), plaintext.as_slice());
}
