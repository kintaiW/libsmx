//! Fuzz target: SM2 验签不 panic（接受任意字节输入）
//!
//! 对任意输入调用 sm2::verify 不应 panic，只能返回 Ok 或 Err。
//! 验证实现对格式错误输入的健壮性。

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 需要至少 32 + 65 + 64 = 161 字节
    if data.len() < 161 {
        return;
    }

    let e: &[u8; 32]   = data[..32].try_into().unwrap();
    let pub_key: &[u8; 65] = data[32..97].try_into().unwrap();
    let sig: &[u8; 64] = data[97..161].try_into().unwrap();

    // 只要不 panic 即可；Ok 或 Err 都是合法结果
    let _ = sm2::verify(e, pub_key, sig);
});
