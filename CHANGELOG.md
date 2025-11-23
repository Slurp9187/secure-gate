# Changelog

All changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2025-11-24

### Added
- `fixed_alias!` types now support idiomatic construction via `From` and `.into()`
  ```rust
  fixed_alias!(Aes256Key, 32);

  let key1 = Aes256Key::from(rng.gen());
  let key2: Aes256Key = rng.gen().into();  // natural, zero-cost, idiomatic
  ```
- All `fixed_alias!` types automatically inherit `from_slice` and `From<[u8; N]>` from generic impls on `Fixed`

### Changed
- Removed inherent impls from `fixed_alias!` macro (now uses crate-level generic impls)
  - Fixes orphan rule violations
  - Cleaner, more maintainable code
  - No behavior change for users

This release completes the ergonomics vision: `fixed_alias!` types now feel like first-class, built-in secret types.

## [0.5.1] - 2025-11-23

### Added
- New `secure!`, `secure_zeroizing!`, `fixed_alias!`, and `dynamic_alias!` macros for ergonomic secret creation
- Support for heap-based secrets via `secure!(String, ...)` and `secure!(Vec<u8>, ...)`
- `from_slice()` method and `From<[u8; N]>` impl on all `fixed_alias!` types
- `finish_mut()` helper emphasized for eliminating spare capacity in heap secrets
- Comprehensive macro test suite (`tests/macros_tests.rs`) with full feature-gate support

### Changed
- `fixed_alias!` now only emits the type alias; methods are provided via generic impls on `Fixed<[u8; N]>`
- Improved documentation of memory guarantees under the `zeroize` feature
- Macro tests now correctly gated behind `#[cfg(feature = "zeroize")]` to support `--no-default-features`

### Fixed
- README now accurately reflects that `zeroize` performs full-capacity wiping, but does not force deallocation or shrink capacity
- Resolved orphan rule violations in `fixed_alias!` macro
- Fixed privacy and feature-gating issues in test suite and re-exports

## [0.5.0] - 2025-11-22

### Breaking Changes
- Replaced `SecureGate<T>` with two honest types: `Fixed<T>` (stack/fixed-size) and `Dynamic<T>` (heap/dynamic).
- Removed `ZeroizeMode` and manual wiping — `zeroize` ≥1.8 handles spare capacity by default.
- Removed password specializations (`SecurePassword`, `SecurePasswordBuilder`) — use `Dynamic<String>`.
- Removed `unsafe-wipe` — safe by default.
- Migration guide in README.

### Added
- True zero-cost for fixed-size secrets when `zeroize` off (no heap allocation).
- `Deref` / `DerefMut` ergonomics — secrets borrow like normal types.
- `secure!` and `fixed_alias!` macros for constructors and aliases.
- `into_inner()` for extraction.
- `finish_mut()` with `shrink_to_fit` for `Dynamic<String>` / `Vec<u8>`.
- `Clone` for `Dynamic<T>`.

### Fixed
- No `unsafe` when `zeroize` off (`forbid(unsafe_code)`).
- Full spare-capacity wipe via `zeroize`.
- Consistent API across modes.

### Improved
- Modular structure (`fixed.rs`, `dynamic.rs`, `macros.rs`, `zeroize.rs`, `serde.rs`).
- 9 unit tests covering zero-cost, wiping, ergonomics, serde, macros.

## [0.4.3] - 2025-11-20

### Fixed
- Documentation mismatch: `CHANGELOG.md` and `README.md` now correctly reflect the changes shipped in 0.4.2
- No code changes — binary identical to 0.4.2

### Changes in 0.4.2 (now correctly documented)
- Fixed #27: Restored `.expose_secret()` and `.expose_secret_mut()` on `SecurePassword` and `SecurePasswordBuilder`
- `SecurePasswordBuilder` now supports full mutation (`push_str`, `push`, etc.) and `.build()`
- `SecureStackPassword` is now truly zero-heap using `zeroize::Zeroizing<[u8; 128]>`
- All password-specific accessors work correctly under `--no-default-features`
- Added `expose_secret_bytes()` / `expose_secret_bytes_mut()` (gated behind `unsafe-wipe`)
- Added comprehensive regression test suite (`tests/password_tests.rs`) with 8+ guards
- Zero warnings under `cargo clippy --all-features -- -D warnings`

## [0.4.1] - 2025-11-20

### Added
- Configurable zeroization modes via `ZeroizeMode` enum:
  - `Safe` (default) – wipes only used bytes (no unsafe code)
  - `Full` (opt-in via `unsafe-wipe` feature) – wipes entire allocation including spare capacity
  - `Passthrough` – relies solely on inner type's `Zeroize` impl
- New constructors:
  - `SecureGate::new_full_wipe(value)`
  - `SecureGate::new_passthrough(value)`
  - `SecureGate::with_mode(value, mode)`
- Full-capacity wiping now works correctly for `Vec<u8>` and `String` under `unsafe-wipe`

### Changed
- `SecureGate<T>` now stores zeroization mode (zero-cost for non-`Vec<u8>`/`String`)
- All zeroization logic unified through `Wipable` trait

### Fixed
- Empty but allocated vectors are now properly wiped in `Full` mode
- Clone preserves zeroization mode correctly

## [0.4.0] - 2025-11-20

### Breaking Changes (semver-minor)
- Unified all secure wrapper types under a single generic type: `SecureGate<T>`
- `SecureGate<T>` is now the canonical public name

### Added
- New short alias `SG<T>` for `SecureGate<T>`
- Fixed-size secrets use `zeroize::Zeroizing` directly when `stack` feature is enabled

### Deprecated
- Old names `Secure<T>` and `HeapSecure<T>` are now deprecated aliases

## [0.3.4] - 2025-11-18

### Documentation
- Updated README with correct `.expose_secret()` usage

## [0.3.3] - 2025-11-18

### Added
- Direct `.expose_secret()` and `.expose_secret_mut()` on password types

## [0.3.1] - 2025-11-17

### Changed
- Renamed `SecurePasswordMut` → `SecurePasswordBuilder`

## [0.3.0] - 2025-11-13

- Initial public release