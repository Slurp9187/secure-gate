# Changelog

All changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2025-11-20

### Fixed
- **#27**: Fully restored the ergonomic `.expose_secret()` and `.expose_secret_mut()` methods on `SecurePassword` and `SecurePasswordBuilder` — the original regression is **dead forever**
- `SecurePasswordBuilder` now correctly supports full mutation (`push_str`, `push`, etc.) and `.build()`
- `SecureStackPassword` is now truly zero-heap using `zeroize::Zeroizing<[u8; 128]>`
- All password-specific accessors work correctly under `--no-default-features`

### Added
- `expose_secret_bytes()` and `expose_secret_bytes_mut()` (with proper `unsafe-wipe` gating)
- Comprehensive regression test suite (`tests/password_tests.rs`) with 8+ bulletproof guards
- Full support for `cargo test --no-default-features` — compiles and runs cleanly

### Improved
- Zero warnings under `cargo clippy --all-features -- -D warnings`
- All tests pass on every feature combination
- The crate is now **perfectly stable**, **zero warnings**, **fully tested**, and **production-ready**

> This release marks the end of the great password API regression saga.  
> The thorn has been pulled.  
> The crate is healed.  
> You may now use it in peace.

## [0.4.1] - 2025-11-20
### Added
- **Configurable zeroization modes** via `ZeroizeMode` enum:
  - `Safe` (default) – wipes only used bytes (no unsafe code)
  - `Full` (opt-in via `unsafe-wipe` feature) – wipes entire allocation including spare capacity
  - `Passthrough` – relies solely on inner type's `Zeroize` impl
- New constructors:
  - `SecureGate::new_full_wipe(value)` – creates in `Full` mode
  - `SecureGate::new_passthrough(value)` – creates in `Passthrough` mode
  - `SecureGate::with_mode(value, mode)` – explicit mode selection
- Full-capacity wiping now works correctly for both `Vec<u8>` and `String` under `unsafe-wipe`
- New comprehensive regression suite: `tests/mode_tests.rs`

### Changed
- `SecureGate<T>` now stores zeroization mode (zero-cost for non-`Vec<u8>`/`String`)
- All zeroization logic unified through `Wipable` trait
- `unsafe-wipe` feature now has real, observable effect (slack memory is zeroed)

### Fixed
- Empty but allocated vectors are now properly wiped in `Full` mode
- Clone preserves zeroization mode correctly

### Internal
- Refactored zeroization paths for clarity and correctness
- All tests pass under `--all-features` and `--no-default-features`

## [0.4.0] - 2025-11-20
### Breaking Changes (semver-minor)
- Unified all secure wrapper types under a single generic type: `SecureGate<T>`  
  (replaces the previous `HeapSecure` / `Secure<T>` naming)
- `SecureGate<T>` is now the canonical public name and is re-exported at the crate root
- All existing type aliases (`SecurePassword`, `SecureKey32`, `SecureNonce24`, etc.) remain unchanged and continue to work exactly as before

### Added
- New short alias `SG<T>` for `SecureGate<T>`
- Fixed-size secrets now use `zeroize::Zeroizing` directly when the `stack` feature is enabled (zero wrapper overhead)
- All constructors for stack-based keys (`key32`, `nonce24`, etc.) are now available in the crate root

### Changed
- `secure!` macro now expands to `SecureGate::<T>::new(...)`
- Internal modules reorganized for clarity

### Deprecated
- The old names `Secure<T>` and `HeapSecure<T>` are now deprecated aliases pointing to `SecureGate<T>`
- They will be removed in a future 1.0 release

### Fixed
- Resolved remaining trait resolution issues in `no-default-features` mode
- Cleaned up Clippy warnings

## [0.3.4] - 2025-11-18
### Documentation
- Updated README with correct single-call `.expose_secret()` usage examples

## [0.3.3] - 2025-11-18
### Added
- Direct `.expose_secret()` and `.expose_secret_mut()` on `SecurePassword` and `SecurePasswordBuilder`
- `finish_mut()` method on `HeapSecure<String>` and `HeapSecure<Vec<u8>>`

## [0.3.2] - 2025-11-17
### Changed
- Moved `SecurePasswordMut` to `src/deprecated.rs`
- Updated fuzz target to use `SecurePasswordBuilder`

## [0.3.1] - 2025-11-17
### Changed
- Renamed `SecurePasswordMut` → `SecurePasswordBuilder`
- Added `into_password()` and `build()` methods

## [0.3.0] - 2025-11-13
- Initial public release