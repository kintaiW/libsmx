//! Fuzz target: SM4 加密后解密必须还原原始数据
//!
//! 验证对任意 key + block，encrypt 后 decrypt 得到原始 block。

#![no_main]

use libfuzzer_sys::fuzz_target;
use sm4::{Sm4, KeyInit, BlockCipherEncrypt, BlockCipherDecrypt};
use sm4::cipher::array::Array;

fuzz_target!(|data: &[u8]| {
    // 需要至少 32 字节（16 字节 key + 16 字节 block）
    if data.len() < 32 {
        return;
    }

    let key: [u8; 16] = data[..16].try_into().unwrap();
    let block_data: [u8; 16] = data[16..32].try_into().unwrap();

    let cipher = Sm4::new(&Array::from(key));
    let mut block = Array::from(block_data);
    let original = block.clone();

    // 加密
    cipher.encrypt_block(&mut block);
    // 解密
    cipher.decrypt_block(&mut block);

    // 还原检查
    assert_eq!(block, original, "SM4 encrypt then decrypt must restore original");
});
