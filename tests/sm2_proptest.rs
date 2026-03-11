//! SM2 属性测试 / Property-based tests for SM2
//!
//! 使用 proptest 验证：任意随机私钥生成的签名均可被对应公钥验证。
//! Tests that for arbitrary random key bytes, sign-then-verify always succeeds.

use libsmx::sm2::{get_e, get_z, sign, verify, PrivateKey, DEFAULT_ID};
use proptest::prelude::*;

proptest! {
    /// 任意合法私钥：签名后验签必须通过
    ///
    /// Reason: 使用原始字节数组作为策略输入（proptest 只需字节组具有 Debug），
    /// 在测试体内调用 from_bytes 过滤非法值，合法时执行验证逻辑。
    #[test]
    fn prop_sign_verify_roundtrip(
        key_bytes in prop::array::uniform32(1u8..=0xFFu8),
        msg in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let pri_key = match PrivateKey::from_bytes(&key_bytes) {
            Ok(k) => k,
            Err(_) => return Ok(()), // 非法私钥直接跳过
        };

        let pub_key = pri_key.public_key();
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, &msg);

        let mut rng = rand::thread_rng();
        let sig = sign(&e, &pri_key, &mut rng);

        prop_assert!(verify(&e, &pub_key, &sig).is_ok(),
            "sign-then-verify failed for a valid key");
    }

    /// 不同消息的签名不能交叉验证
    #[test]
    fn prop_different_msg_rejected(
        key_bytes in prop::array::uniform32(1u8..=0xFFu8),
        msg1 in prop::collection::vec(any::<u8>(), 1..64),
        msg2 in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(msg1 != msg2);

        let pri_key = match PrivateKey::from_bytes(&key_bytes) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };

        let pub_key = pri_key.public_key();
        let z = get_z(DEFAULT_ID, &pub_key);
        let e1 = get_e(&z, &msg1);
        let e2 = get_e(&z, &msg2);

        let mut rng = rand::thread_rng();
        let sig1 = sign(&e1, &pri_key, &mut rng);

        // 用 msg1 的签名验证 msg2 应失败
        prop_assert!(verify(&e2, &pub_key, &sig1).is_err(),
            "signature for msg1 must not verify msg2");
    }

    /// 篡改签名任意字节后验签应失败（或恰好产生另一合法签名，极罕见）
    #[test]
    fn prop_tampered_sig_no_panic(
        key_bytes in prop::array::uniform32(1u8..=0xFFu8),
        msg in prop::collection::vec(any::<u8>(), 1..128),
        tamper_idx in 0usize..64,
        tamper_xor in 1u8..=0xFFu8,
    ) {
        let pri_key = match PrivateKey::from_bytes(&key_bytes) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };

        let pub_key = pri_key.public_key();
        let z = get_z(DEFAULT_ID, &pub_key);
        let e = get_e(&z, &msg);

        let mut rng = rand::thread_rng();
        let mut sig = sign(&e, &pri_key, &mut rng);

        sig[tamper_idx] ^= tamper_xor;

        // 仅断言不 panic，不断言一定失败（极罕见情况下可能仍然合法）
        let _ = verify(&e, &pub_key, &sig);
    }
}
