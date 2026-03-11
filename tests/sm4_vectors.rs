//! SM4 国标测试向量（GB/T 32907-2016 附录 A）
//!
//! A.1 示例1：单次 ECB 加密（单块）
//! A.2 示例2：1,000,000 次迭代 ECB 加密（验证算法迭代正确性）
//!
//! 注：原来使用 `sm4_encrypt_ecb` 的向量测试已迁移为直接使用 `Sm4Key::encrypt_block`，
//! 与 RustCrypto 生态的 `sm4` 子 crate 行为一致。

use libsmx::sm4::Sm4Key;

/// GB/T 32907-2016 附录 A.1
/// 密钥：0123456789abcdeffedcba9876543210
/// 明文：0123456789abcdeffedcba9876543210
/// 密文：681edf34d206965e86b3e94f536e4246
#[test]
fn test_sm4_ecb_vector_a1_single() {
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let key_arr: [u8; 16] = key.try_into().unwrap();
    let sm4 = Sm4Key::new(&key_arr);

    let mut block = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let block_arr: &mut [u8; 16] = block.as_mut_slice().try_into().unwrap();

    sm4.encrypt_block(block_arr);

    let expected = hex::decode("681edf34d206965e86b3e94f536e4246").unwrap();
    assert_eq!(block_arr, expected.as_slice(), "GB/T 32907 附录 A.1 加密失败");

    sm4.decrypt_block(block_arr);
    let plaintext = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    assert_eq!(block_arr, plaintext.as_slice(), "GB/T 32907 附录 A.1 解密失败");
}

/// GB/T 32907-2016 附录 A.2
/// 密钥：0123456789abcdeffedcba9876543210
/// 明文：0123456789abcdeffedcba9876543210（反复迭代 1,000,000 次）
/// 密文：595298c7c6fd271f0402f804c33d3f66
#[test]
#[ignore = "slow (1M iterations)"]
fn test_sm4_ecb_vector_a2_million_iterations() {
    let key: [u8; 16] = hex::decode("0123456789abcdeffedcba9876543210")
        .unwrap()
        .try_into()
        .unwrap();
    let sm4 = Sm4Key::new(&key);

    let mut block: [u8; 16] = hex::decode("0123456789abcdeffedcba9876543210")
        .unwrap()
        .try_into()
        .unwrap();

    for _ in 0..1_000_000 {
        sm4.encrypt_block(&mut block);
    }

    let expected = hex::decode("595298c7c6fd271f0402f804c33d3f66").unwrap();
    assert_eq!(&block, expected.as_slice(), "GB/T 32907 附录 A.2 百万次迭代失败");
}

/// 加解密往返测试
#[test]
fn test_sm4_block_roundtrip() {
    let key = [0x01u8; 16];
    let sm4 = Sm4Key::new(&key);
    let plaintext = *b"SM4 ECB test!!!!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut block: [u8; 16] = plaintext[..16].try_into().unwrap();
    sm4.encrypt_block(&mut block);
    assert_ne!(block, plaintext[..16], "密文应与明文不同");
    sm4.decrypt_block(&mut block);
    assert_eq!(block, plaintext[..16], "解密后应恢复原文");
}
