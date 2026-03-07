# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-03-07

### Fixed

- Fixed `cargo test --no-default-features --lib` compilation error
  - SM3 tests: removed alloc dependency, use manual hex parsing
  - SM4 modes tests: added `#[cfg(feature = "alloc")]`

### Changed

- MSRV raised to 1.83.0 (required by crypto-bigint 0.6.x for ConstMontyForm constant-time Montgomery arithmetic)
- Use Rust 1.83+ built-in `div_ceil` method instead of manual implementation

### CI

- Optimized sanity_check.sh to skip test code, avoiding false positives

## [0.1.0] - 2025-03-07

### Added

- SM2 elliptic curve cryptography (GB/T 32918.1-5-2016)
  - Key generation, digital signature (with Z-value), public key encryption/decryption
  - Complete addition formulas for constant-time point operations
  - Fixed-window (w=4) base point scalar multiplication with precomputed table
  - Mixed Jacobian-Affine addition for optimized verification (Shamir's trick)
  - Point compression/decompression (GB/T 32918.1 section 4.2.10)
- SM3 cryptographic hash (GB/T 32905-2016)
  - Streaming and one-shot hashing API
  - HMAC-SM3 with automatic key material zeroization
- SM4 block cipher (GB/T 32907-2016)
  - Boolean circuit bitslice S-box (cache-timing resistant)
  - 8 modes of operation: ECB, CBC, OFB, CFB, CTR, GCM, CCM, XTS
  - GCM/CCM authenticated encryption with constant-time tag verification
- SM9 identity-based cryptography (GB/T 38635.1-2-2020)
  - BN256 pairing (optimal Ate with Miller loop + final exponentiation)
  - Fp12 tower extension: Fp -> Fp2(u^2+2) -> Fp6(v^3-u) -> Fp12(w^2-v)
  - Identity-based signing and verification
  - Identity-based encryption and decryption
- Unified `Error` enum with `Display` and conditional `std::error::Error` impl
- `no_std` support with optional `alloc` and `std` features
- `#![forbid(unsafe_code)]` enforced at crate level
- Automatic private key zeroization via `zeroize::ZeroizeOnDrop`
- GB/T standard test vectors for all algorithms
- Criterion benchmarks for all algorithms with baseline performance data:
  - SM3: 374 MiB/s throughput (64 KiB)
  - SM4-ECB: 27 MiB/s throughput (64 KiB)
  - SM2 sign: 258 µs, verify: 316 µs
  - SM9 sign: 3.44 ms, verify: 5.50 ms

### Changed

- MSRV raised to 1.83.0 (required by crypto-bigint 0.6.x for ConstMontyForm constant-time Montgomery arithmetic)

### Security

- GCM `gf128_mul`: replaced secret-dependent `if` branches with mask arithmetic
- SM2 `is_infinity`: replaced short-circuit `Iterator::all` with `ConstantTimeEq`
- SM2 `add`: replaced 3 conditional branches with complete addition formulas + `conditional_select`
- SM2 `double`: replaced `if is_infinity()` with `conditional_select`
- HMAC-SM3: added `zeroize` for `k_pad`/`ipad`/`opad` key material on stack
- CCM: reject AAD > 510 bytes instead of silently skipping
- XTS: reject non-16-byte-aligned input instead of silently truncating
- SM9 `hash_to_range`: replaced variable-iteration `while` loop with constant-time conditional select

[0.1.1]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.1
[0.1.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.0
