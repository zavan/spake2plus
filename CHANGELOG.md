# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-04

### Added

- SPAKE2+ (RFC 9383) for both roles, `Prover` and `Verifier`, `no_std`
  without `alloc`.
- The suites `P256Sha256` (P-256, SHA-256, HKDF-SHA256, HMAC-SHA256) and
  `P256Sha512` (P-256, SHA-512, HKDF-SHA512, HMAC-SHA512), each checked
  against RFC 9383's test vectors.
- Registration from a caller's password hash output
  (`ProverSecret::from_pbkdf_output`) and the verifier's stored record
  (`VerifierRecord`), both refusing a zero `w0` or `w1`.
- Typed messages that refuse malformed shares, points off the curve, the
  identity and shares that cancel the password's mask.
- Constant-time confirmation checks, sessions that each step consumes, and
  `ProverConfirming::confirm_first` for protocols that send the prover's
  confirmation first.
- Zeroization on drop of every secret.

[Unreleased]: https://github.com/zavan/spake2plus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zavan/spake2plus/releases/tag/v0.1.0
