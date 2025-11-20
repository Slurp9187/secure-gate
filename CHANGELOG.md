# Changelog

All changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Internal modules reorganized for clarity:
  - `heap.rs` → `secure_gate.rs`
  - `stack.rs` → `fixed_stack.rs`
- Removed unnecessary wrapper types (`StackSecure`) and redundant trait implementations

### Deprecated
- The old names `Secure<T>` and `HeapSecure<T>` are now deprecated aliases pointing to `SecureGate<T>`
- They will be removed in a future 1.0 release
- A comprehensive `deprecated` module keeps all 0.3.x code compiling with only deprecation warnings

### Fixed
- Resolved remaining trait resolution issues in `no-default-features` mode
- Cleaned up Clippy warnings and ensured zero unexpected warnings on fresh builds

## [0.3.4] - 2025-11-18
### Documentation
- Updated README with correct single-call `.expose_secret()` usage examples

## [0.3.3] - 2025-11-18
### Added
- Direct `.expose_secret()` and `.expose_secret_mut()` on `SecurePassword` and `SecurePasswordBuilder`  
  (eliminates the previous double-call `.expose().expose_secret()`)
- `finish_mut()` method on `HeapSecure<String>` and `HeapSecure<Vec<u8>>` (available with or without the `zeroize` feature)

## [0.3.2] - 2025-11-17
### Changed
- Moved `SecurePasswordMut` to `src/deprecated.rs` with proper module hygiene
- Updated fuzz target to use `SecurePasswordBuilder` (removes deprecation warnings in CI)

### Fixed
- Minor documentation spelling (“deprecated” instead of “depreciated”)

## [0.3.1] - 2025-11-17
### Changed
- Renamed `SecurePasswordMut` → `SecurePasswordBuilder` for clarity and builder-pattern familiarity  
  - `SecurePasswordMut` is now a **deprecated alias** with a compiler warning  
  - No breaking change — existing code continues to compile
- Added `into_password()` and `build()` methods on `SecurePasswordBuilder` for ergonomic conversion to the immutable `SecurePassword`
- All public aliases (`SecurePassword`, `SecurePasswordBuilder`, `SecureBytes`, `SecureStr`, etc.) are now available even when the `zeroize` feature is disabled  
  (fixes compilation and testing with `--no-default-features`)

### Fixed
- Resolved trait conflicts in `no-default-features` mode
- Improved test assertions to use `.expose()` directly (more idiomatic)

## [0.3.0] - 2025-11-13
- Initial public release
- Zero-overhead secure wrappers with optional `zeroize` and `stack` features
- Core types: `Secure<T>`, `SecureBytes`, `SecureStr`, fixed-size key types, and password aliases