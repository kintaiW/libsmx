# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in libsmx, please report it responsibly:

**Email**: [kintai@foxmail.com](mailto:kintai@foxmail.com)

**Please include**:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Any potential impact assessment

**Response timeline**:

This project is maintained by an individual. No fixed response time is guaranteed. The author will handle all security reports as soon as possible, but cannot commit to specific timelines.

## Scope

The following areas are considered in-scope for security reports:

- **Timing side-channels**: Any operation whose execution time depends on secret data (private keys, plaintext, nonces)
- **Memory safety**: Buffer overflows, use-after-free, or uninitialized memory reads (note: this crate uses `#![forbid(unsafe_code)]`)
- **Key material leakage**: Private keys or intermediate secret values not properly zeroized
- **Cryptographic correctness**: Deviations from GB/T standards that weaken security guarantees
- **Authentication bypass**: Incorrect MAC/tag verification in GCM/CCM modes

## Out of Scope

- Performance issues that don't affect security
- Dependencies' vulnerabilities (report upstream)
- Attacks requiring physical access to the device

## Security Design

libsmx employs the following defenses:

- **Constant-time operations**: All secret-dependent code uses `subtle::ConstantTimeEq`, `ConditionallySelectable`, and fixed-iteration loops
- **No table lookups for S-boxes**: SM4 uses boolean circuit bitslice implementation to prevent cache-timing attacks
- **Automatic key zeroization**: All private key types derive `ZeroizeOnDrop`
- **No unsafe code**: `#![forbid(unsafe_code)]` is enforced at the crate level
- **Complete EC formulas**: SM2 point addition uses branch-free complete addition formulas (Renes-Costello-Batina 2016)

## Disclosure Policy

We follow coordinated disclosure. Please do **not** open public GitHub issues for security vulnerabilities.
