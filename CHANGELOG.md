# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - v0.2.0

### Added

- **BLS signatures** (`bls` module, requires `alloc` feature)
  - `bls_keygen` / `bls_sign` / `bls_verify`: minimal-signature-size variant (sig ∈ G1, pk ∈ G2)
  - `bls_aggregate` / `bls_aggregate_verify`: multi-message aggregate signatures
  - `bls_fast_aggregate_verify`: fast aggregate verification for same-message multi-signer
  - `BlsSignature::to_bytes` / `from_bytes`: 65-byte serialization (uncompressed G1 point)
  - `BlsPubKey::to_bytes` / `from_bytes`: 128-byte serialization (uncompressed G2 point)
- **BLS threshold signatures** (`bls::threshold` module)
  - `bls_threshold_keygen`: Trusted Dealer mode, Shamir polynomial secret sharing
  - `bls_partial_sign` / `bls_combine_signatures`: Lagrange interpolation based aggregation
  - Supports (t+1, n) threshold configurations
- **Hash-to-Curve** (`bls::hash_to_curve` module)
  - `hash_to_g1`: RFC 9380 compliant, maps arbitrary message to BN256 G1 point
  - `expand_message_xmd`: RFC 9380 §5.3.1, message expansion using SM3 as hash
  - `map_to_curve_svdw`: Shallue-van de Woestijne mapping for BN256 (a=0 curve)
- **`fp_sqrt`** in `sm9::fields::fp`
  - Tonelli-Shanks modular square root for SM9 BN256 Fp (p ≡ 1 mod 4)
  - `fp_is_square`: Euler criterion based quadratic residue test
- **FPE format-preserving encryption** (`fpe` module)
  - `FpeKey`: 7-round Luby-Rackoff Feistel cipher based on SM4
  - Supports 1~128 bit plaintext/ciphertext domains
  - `expand_tweak`: arbitrary-length tweak via SM4 hash
  - Automatic key zeroization on drop (`ZeroizeOnDrop`)

### Security

- BLS signature DST separation: signing uses `BLS_SIG_SM9G1_XMD:SM3_SVDW_RO_NUL_`, PoP uses a different tag
- BN256 security note: ~100-bit actual security level documented in API docs

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

[0.2.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.2.0
[0.1.1]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.1
[0.1.0]: https://github.com/kintaiW/libsmx/releases/tag/v0.1.0
