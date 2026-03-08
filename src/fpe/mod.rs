//! FPE（Format-Preserving Encryption）保留格式加密
//!
//! 基于 FNR（Flexible Naor-Reingold）算法，使用 SM4 作为底层密码：
//! - 支持 1~128 位任意长度的明密文域
//! - 明密文在同一域内（位数相同）
//! - 支持 tweak（调整值）参数化加密
//!
//! # 使用示例
//!
//! ```rust
//! # #[cfg(feature = "alloc")]
//! # {
//! use libsmx::fpe::FpeKey;
//!
//! let key = [0u8; 16];
//! let fpe = FpeKey::new(&key, 32).unwrap(); // 32 位域（如 IPv4 地址）
//! let tweak = fpe.expand_tweak(b"my-tweak");
//!
//! let plaintext: u32 = 192_168_1_100; // 某 IPv4 地址
//! let mut data = plaintext.to_be_bytes();
//! let mut block = [0u8; 16];
//! block[..4].copy_from_slice(&data);
//!
//! fpe.encrypt(&tweak, &mut block);
//! fpe.decrypt(&tweak, &mut block);
//!
//! assert_eq!(&block[..4], &data);
//! # }
//! ```

mod fnr;

use crate::error::Error;
use crate::sm4::Sm4Key;
use fnr::{clear_high_bits, fnr_decrypt, fnr_encrypt};
use zeroize::ZeroizeOnDrop;

/// FPE 扩展 tweak（15 字节）
///
/// 由 `FpeKey::expand_tweak` 从任意长度的 tweak 字节生成。
#[derive(Clone, Copy)]
pub struct FpeTweak([u8; 15]);

/// FPE 密钥（SM4 密钥 + 位数配置）
///
/// 使用 ZeroizeOnDrop 确保密钥在 Drop 时自动清零。
#[derive(ZeroizeOnDrop)]
pub struct FpeKey {
    /// 底层 SM4 密钥
    key: Sm4Key,
    /// 有效位数（1~128）
    num_bits: usize,
}

impl FpeKey {
    /// 创建 FPE 密钥
    ///
    /// # 参数
    /// - `key`：16 字节 SM4 密钥
    /// - `num_bits`：明密文域的位数（1~128）
    ///
    /// # 错误
    /// - `Error::InvalidInputLength`：`num_bits` 不在 1~128 范围内
    pub fn new(key: &[u8; 16], num_bits: usize) -> Result<Self, Error> {
        if num_bits == 0 || num_bits > 128 {
            return Err(Error::InvalidInputLength);
        }
        Ok(FpeKey {
            key: Sm4Key::new(key),
            num_bits,
        })
    }

    /// 将任意长度的 tweak 扩展为 15 字节内部 tweak
    ///
    /// 使用 SM4 对 tweak 进行哈希（CBC-MAC 风格）得到固定长度输出。
    pub fn expand_tweak(&self, tweak: &[u8]) -> FpeTweak {
        // 用 SM4 对 tweak 进行"哈希"：
        // 将 tweak 分块，每块 XOR 进状态后 SM4 加密
        let mut state = [0u8; 16];
        // 存储 num_bits 到 state 前 2 字节（域参数绑定）
        state[0] = (self.num_bits >> 8) as u8;
        state[1] = self.num_bits as u8;

        for chunk in tweak.chunks(16) {
            let mut block = state;
            for (i, &b) in chunk.iter().enumerate() {
                block[i] ^= b;
            }
            self.key.encrypt_block(&mut block);
            state = block;
        }

        // 最终加密（确保即使 tweak 为空也有输出）
        self.key.encrypt_block(&mut state);

        let mut out = [0u8; 15];
        out.copy_from_slice(&state[..15]);
        FpeTweak(out)
    }

    /// 就地加密（前 num_bits 位）
    ///
    /// `data` 的前 `num_bits` 位被加密，高于 `num_bits` 的位保持不变。
    ///
    /// # 注意
    /// `data` 的位顺序：字节 0 的最高位是位 0（高位优先）。
    pub fn encrypt(&self, tweak: &FpeTweak, data: &mut [u8; 16]) {
        // 保存高于 num_bits 的位（不应被修改）
        let saved = save_high_bits(data, self.num_bits);
        clear_high_bits(data, self.num_bits);
        fnr_encrypt(&self.key, &tweak.0, data, self.num_bits);
        restore_high_bits(data, &saved, self.num_bits);
    }

    /// 就地解密（前 num_bits 位）
    pub fn decrypt(&self, tweak: &FpeTweak, data: &mut [u8; 16]) {
        let saved = save_high_bits(data, self.num_bits);
        clear_high_bits(data, self.num_bits);
        fnr_decrypt(&self.key, &tweak.0, data, self.num_bits);
        restore_high_bits(data, &saved, self.num_bits);
    }

    /// 返回有效位数
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
}

/// 保存 data 中高于 n 位的位（用于还原）
fn save_high_bits(data: &[u8; 16], n: usize) -> [u8; 16] {
    let mut saved = [0u8; 16];
    let full_bytes = n / 8;
    let rem = n % 8;
    if rem != 0 && full_bytes < 16 {
        // 保存 full_bytes 字节的高位部分（低 (8-rem) 位）
        let mask = 0xFF_u8 >> rem;
        saved[full_bytes] = data[full_bytes] & mask;
    }
    let start = full_bytes + if rem > 0 { 1 } else { 0 };
    saved[start..16].copy_from_slice(&data[start..16]);
    saved
}

/// 将保存的高位还原到 data
fn restore_high_bits(data: &mut [u8; 16], saved: &[u8; 16], n: usize) {
    let full_bytes = n / 8;
    let rem = n % 8;
    if rem != 0 && full_bytes < 16 {
        let mask = 0xFF_u8 >> rem; // 低 (8-rem) 位
        data[full_bytes] = (data[full_bytes] & !mask) | (saved[full_bytes] & mask);
    }
    let start = full_bytes + if rem > 0 { 1 } else { 0 };
    data[start..16].copy_from_slice(&saved[start..16]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpe_new_valid() {
        assert!(FpeKey::new(&[0u8; 16], 1).is_ok());
        assert!(FpeKey::new(&[0u8; 16], 32).is_ok());
        assert!(FpeKey::new(&[0u8; 16], 128).is_ok());
    }

    #[test]
    fn test_fpe_new_invalid() {
        assert!(FpeKey::new(&[0u8; 16], 0).is_err());
        assert!(FpeKey::new(&[0u8; 16], 129).is_err());
    }

    #[test]
    fn test_fpe_encrypt_decrypt_roundtrip_32bits() {
        let key = [0x01u8; 16];
        let fpe = FpeKey::new(&key, 32).unwrap();
        let tweak = fpe.expand_tweak(b"test-tweak");

        // 明文：u32 = 12345678
        let mut data = [0u8; 16];
        data[..4].copy_from_slice(&12345678u32.to_be_bytes());
        let original = data;

        fpe.encrypt(&tweak, &mut data);
        // 加密后应与原始不同
        assert_ne!(&data[..4], &original[..4], "加密后数据应变化");
        // 解密后应恢复原始
        fpe.decrypt(&tweak, &mut data);
        assert_eq!(&data[..4], &original[..4], "解密后应恢复原始明文");
    }

    #[test]
    fn test_fpe_encrypt_decrypt_roundtrip_8bits() {
        let key = [0xABu8; 16];
        let fpe = FpeKey::new(&key, 8).unwrap();
        let tweak = fpe.expand_tweak(b"tweak");

        for val in 0u8..=255 {
            let mut data = [0u8; 16];
            data[0] = val;
            let original = data;

            fpe.encrypt(&tweak, &mut data);
            fpe.decrypt(&tweak, &mut data);
            assert_eq!(data[0], original[0], "8位加解密往返应还原 val={}", val);
        }
    }

    #[test]
    fn test_fpe_encrypt_decrypt_roundtrip_1bit() {
        let key = [0x99u8; 16];
        let fpe = FpeKey::new(&key, 1).unwrap();
        let tweak = fpe.expand_tweak(b"");

        // 测试 0 和 1
        for val in [0u8, 0x80u8] {
            let mut data = [0u8; 16];
            data[0] = val;
            let original = data;
            fpe.encrypt(&tweak, &mut data);
            fpe.decrypt(&tweak, &mut data);
            assert_eq!(data[0] & 0x80, original[0] & 0x80, "1位加解密往返应还原");
        }
    }

    #[test]
    fn test_fpe_encrypt_decrypt_roundtrip_128bits() {
        let key = [0x55u8; 16];
        let fpe = FpeKey::new(&key, 128).unwrap();
        let tweak = fpe.expand_tweak(b"full block");

        let mut data = [0u8; 16];
        for (i, d) in data.iter_mut().enumerate() {
            *d = i as u8 * 17;
        }
        let original = data;

        fpe.encrypt(&tweak, &mut data);
        fpe.decrypt(&tweak, &mut data);
        assert_eq!(data, original, "128位加解密往返应还原");
    }

    #[test]
    fn test_fpe_different_tweaks_different_output() {
        let key = [0x42u8; 16];
        let fpe = FpeKey::new(&key, 32).unwrap();
        let tweak1 = fpe.expand_tweak(b"tweak1");
        let tweak2 = fpe.expand_tweak(b"tweak2");

        let mut d1 = [0u8; 16];
        let mut d2 = [0u8; 16];
        d1[0] = 0xDE;
        d1[1] = 0xAD;
        d1[2] = 0xBE;
        d1[3] = 0xEF;
        d2[..4].copy_from_slice(&d1[..4]);

        fpe.encrypt(&tweak1, &mut d1);
        fpe.encrypt(&tweak2, &mut d2);
        assert_ne!(&d1[..4], &d2[..4], "不同 tweak 应产生不同密文");
    }

    #[test]
    fn test_fpe_high_bits_preserved() {
        // 验证高于 num_bits 的位在加密后不变
        let key = [0x11u8; 16];
        let fpe = FpeKey::new(&key, 4).unwrap(); // 只用高 4 位
        let tweak = fpe.expand_tweak(b"t");

        let mut data = [0u8; 16];
        // 高 4 位为 0b1010，低 4 位为 0b0101
        data[0] = 0b1010_0101;
        // 字节 1~15 也有数据
        for (i, d) in data[1..].iter_mut().enumerate() {
            *d = (i + 1) as u8;
        }
        let saved_low = data[0] & 0x0F;
        let saved_rest: [u8; 15] = data[1..].try_into().unwrap();

        fpe.encrypt(&tweak, &mut data);

        // 低 4 位和字节 1~15 应保持不变
        assert_eq!(data[0] & 0x0F, saved_low, "低4位应不变");
        assert_eq!(&data[1..], &saved_rest, "字节1~15应不变");

        // 解密后高 4 位应恢复
        let encrypted_high = data[0] & 0xF0;
        fpe.decrypt(&tweak, &mut data);
        assert_eq!(data[0] & 0xF0, 0b1010_0000, "解密后高4位应恢复");
        let _ = encrypted_high;
    }
}
