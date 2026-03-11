//! Fuzz target: SM3 一次性哈希与流式哈希必须一致
//!
//! 验证 Sm3::digest(data) == 逐字节 Sm3::update + finalize 的结果相同。

#![no_main]

use libfuzzer_sys::fuzz_target;
use sm3::Digest;

fuzz_target!(|data: &[u8]| {
    // 一次性哈希
    let hash1 = sm3::Sm3::digest(data);

    // 流式哈希（逐字节）
    let mut h = sm3::Sm3::new();
    for byte in data {
        h.update(&[*byte]);
    }
    let hash2 = h.finalize();

    assert_eq!(hash1, hash2, "one-shot and streaming SM3 must agree");
});
