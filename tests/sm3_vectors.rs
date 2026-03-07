//! SM3 国标测试向量（GB/T 32905-2016 附录 A）
//!
//! A.1 示例1：消息为 "abc"（3 字节）
//! A.2 示例2：消息为 "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"（64 字节）

use libsmx::sm3::Sm3Hasher;

/// GB/T 32905-2016 附录 A.1
/// 输入：M = "abc"
/// 预期：66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
#[test]
fn test_sm3_vector_a1_abc() {
    let msg = b"abc";
    let digest = Sm3Hasher::digest(msg);
    let expected = hex::decode("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        .unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "GB/T 32905 附录 A.1 失败");
}

/// GB/T 32905-2016 附录 A.2
/// 输入：M = "abcd" × 16（64 字节）
/// 预期：debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
#[test]
fn test_sm3_vector_a2_64bytes() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let digest = Sm3Hasher::digest(msg);
    let expected = hex::decode("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732")
        .unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "GB/T 32905 附录 A.2 失败");
}

/// 流式接口与单次接口结果一致性验证
#[test]
fn test_sm3_streaming_equals_oneshot() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let one_shot = Sm3Hasher::digest(msg);

    let mut h = Sm3Hasher::new();
    h.update(&msg[..32]);
    h.update(&msg[32..]);
    let streaming = h.finalize();

    assert_eq!(one_shot, streaming, "流式与单次结果不一致");
}

/// 空消息哈希测试
/// SM3("") = 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b
#[test]
fn test_sm3_empty_message() {
    let digest = Sm3Hasher::digest(b"");
    let expected = hex::decode("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")
        .unwrap();
    assert_eq!(digest.as_slice(), expected.as_slice(), "SM3 空消息测试失败");
}
