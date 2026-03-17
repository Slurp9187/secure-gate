# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0-alpha.1] - 2026-03-16

**Major breaking alpha release + critical security fix**

### Security

- **CRITICAL: Fixed zeroize-on-drop security flaw** (affects all versions 0.1.0–0.7.0-rc.15)  
  **Issue**: Despite documentation claiming "secrets are zeroized on drop", no `impl Drop` existed — only the empty `ZeroizeOnDrop` marker trait. Secrets were **never wiped** automatically on drop, creating a false sense of security.  
  **Impact**: All users relying on the documented guarantee had secrets persist in memory after drop, potentially exposing sensitive data to memory dumps, swap files, or other processes.  
  **Root cause**: Rust's E0367 rule prevents `Drop` impls with bounds stricter than struct bounds. The optional `zeroize` feature created conflicting bounds.  
  **Fix**: Made `zeroize` mandatory (no feature gate), added `T: Zeroize` bounds to struct definitions, and implemented real `Drop` handlers that call `zeroize()`. Zeroization is now guaranteed.  
  **Migration**: Users wrapping non-zeroizable types must implement `Zeroize` on them. Most crypto types already implement `Zeroize` out of the box.

- **All previous versions yanked**: 0.1.0 through 0.7.0-rc.15 were permanently yanked from crates.io on 2026-03-16 due to the above flaw.

### Breaking Changes

- `zeroize` is now a **required dependency** — no feature gate.
- `Fixed<T>` now requires `T: Zeroize`; `Dynamic<T>` requires `T: ?Sized + Zeroize`.
- Removed `zeroize`, `insecure`, `secure`, and `std` feature aliases entirely.
- `default` is now `["alloc"]` — users who had `features = ["secure"]` can drop it (already included by default).
- `no-alloc` builds remain possible for `Fixed<T>` (zeroize uses `default-features = false`).

### Added

- **Zeroize integration test suite** (`tests/zeroize_tests.rs` rewrite, issue #93)  
  Eight deterministic tests adapted from upstream RustCrypto/zeroize patterns
  (`zeroize/tests/zeroize.rs`, `zeroize/tests/zeroize_derive.rs`):
  - `fixed_direct_zeroize` — explicit `.zeroize()` zeroes `Fixed<[u8; 32]>` contents; verified via `expose_secret()`
  - `fixed_zeroize_on_drop` — `PanicOnNonZeroDrop` sentinel confirms `Fixed::drop` calls `zeroize()` before inner `Drop` runs; no `unsafe`, Miri-clean
  - `fixed_needs_drop` — `core::mem::needs_drop::<Fixed<[u8; 32]>>()` proves a real `Drop` glue destructor exists (would have returned `false` in all pre-0.8.0 versions — single-line regression proof for issue #92)
  - `dynamic_direct_zeroize_vec` / `dynamic_direct_zeroize_string` — `.zeroize()` empties the heap contents of `Dynamic<Vec<u8>>` and `Dynamic<String>`
  - `dynamic_spare_capacity_vec_zeroized` — `PanicOnNonZeroDrop` + `set_len` restore pattern verifies `Vec::zeroize()` byte-zeroes spare capacity (memory beyond `len` but within `cap`) via `with_secret_mut`
  - `dynamic_needs_drop` / `dynamic_needs_drop_string` — confirms real destructors exist for both heap variants

- **Heap-level zeroize verification** (`tests/heap_zeroize.rs`, issue #93)  
  Dedicated integration test binary with a `ProxyAllocator` (adapted from upstream
  `zeroize/tests/alloc.rs`) that intercepts OS deallocations and asserts all bytes of a
  `Dynamic<[u8; 64]>` backing allocation are zero before the memory is freed. Uses an
  `AtomicBool` guard to confine the assertion to the test's lifetime, preventing false
  positives from unrelated test-harness allocations of the same size.

### Changed

- Zeroization is no longer optional — always enabled and enforced.
- Documentation updated throughout to reflect mandatory zeroize requirement.
- `alloc` feature now enables `zeroize/alloc` for full spare-capacity wiping in `Dynamic<Vec<T>>`/`Dynamic<String>`.

### Migration

- Update code to satisfy `T: Zeroize` (most real secrets already do).
- Replace any remaining optional-zeroize assumptions with mandatory behavior.

## [0.7.0-rc.1 through 0.7.0-rc.15] - YANKED (2026-03-16)

**All 0.7.0 release candidates were permanently yanked** from crates.io due to the critical zeroize-on-drop documentation flaw described in 0.8.0.  
These versions are no longer available and the repository was made private shortly after.

The following changes were developed during the 0.7.0-rc period (preserved for historical reference):

### Added

- **Polymorphic access traits**  
`ExposeSecret` and `ExposeSecretMut` traits provide generic, zero-cost access with metadata (`len()`, `is_empty()`) without exposing contents. Implemented for both `Dynamic<T>` and `Fixed<T>`.
- **Timing-safe equality**  
`ConstantTimeEq` trait (`ct-eq` feature) with `.ct_eq()` methods on `Fixed<[u8; N]>` and `Dynamic<T: AsRef<[u8]>>`.
- **Fast probabilistic equality for large secrets**  
`ConstantTimeEqExt` trait (requires `ct-eq-hash` feature) extends `ConstantTimeEq` with methods for fast probabilistic equality using BLAKE3 hashing. Includes `ct_eq_hash()` for direct hash comparison and `ct_eq_auto()` for smart hybrid selection. Centralized threshold logic with default 32-byte crossover point.
- **Configurable decode priority in `try_decode_any`**  
Added optional `priority: Option<&[Format]>` parameter for customizable decode order. Backward compatible with default (Bech32 → Hex → Base64url).
- **Enhanced decoding errors with hints**  
`DecodingError` variants include hints (e.g., attempted formats) in debug builds only.
- `alloc` and `no-alloc` features for explicit heap control.
- `secure` includes `alloc` by default.
- `std` feature depends on `alloc`.
- **Per-format encoding/decoding traits** (orthogonal `ToHex`/`FromHexStr`, etc.)
- **Opt-in cloning & serialization** (`CloneableSecret`, `SerializableSecret` markers)
- **Secure random generation** (`from_random()` using `OsRng`)
- **Fallible fixed-size construction** (`TryFrom<&[u8]>` with `FromSliceError`)
- **Centralized errors** via `thiserror`
- Additional alias macros

### Changed

- **Error hardening with debug/release split** — detailed info in debug, generic in release.
- Testing & CI improvements (`trybuild`, serde fuzz, full feature matrix)
- Documentation overhaul (`SECURITY.md`, README, rustdoc)
- Serde support split into `serde-deserialize` and `serde-serialize` (gated by marker)

(Older versions below were also yanked but are preserved for history.)

## [0.6.1] - 2025-12-07 (yanked)

### Security

- Removed `into_inner()` from main wrappers (closes security bypass)
- Removed `finish_mut()` from heap types (bypassed exposure gate)

### Added

- Ergonomic RNG conversions (`FixedRng<N>` → `Fixed`)
- Convenience random generation methods

### Changed

- Macro visibility now requires explicit `pub` (no automatic fallback)

### Fixed

- Macro recursion in `dynamic_generic_alias!`

## [0.6.0] - 2025-12-06 (yanked)

### Breaking Changes

- Removed `Deref`/`DerefMut`, made inner fields private
- Removed inherent conversion methods (now trait-based)
- Replaced `RandomBytes<N>` with `FixedRng<N>`
- Removed `serde` feature (now gated by marker)
- Switched RNG to direct `OsRng`

### Added

- `len()`/`is_empty()` on fixed arrays
- Compile-time negative impl guard
- Direct `OsRng` usage

### Fixed

- Lifetime issues in RNG
- `ct_eq` bounds

### Performance

- Direct `OsRng` improved keygen throughput 8–10%

## [0.5.10] - 2025-12-02 (yanked)

### Added

- `HexString` and `RandomHex` newtypes
- `PartialEq`/`Eq` for `Dynamic<T>`
- `RandomBytes<N>` newtype
- `random_alias!` macro
- Paranoia test suites

### Changed

- Renamed randomness methods to `.new()`
- Updated doc examples

### Fixed

- Privacy/import issues
- Doc-test failures
- Test assertions
- Macro expansion/orphan rules

## [0.5.9] - 2025-11-30 (yanked)

### Security & API Improvement

- All conversion methods now require explicit `.expose_secret()`

## [0.5.8] - 2025-11-29 (yanked)

### Added

- Optional `conversions` feature for `.to_hex()`, `.to_base64url()`, etc.

## [0.5.7] - 2025-11-27 (yanked)

### Added

- `rand` feature with `SecureRandomExt::random()`

### Documentation

- Complete rustdoc overhaul

## [0.5.6] - 2025-04-05 (yanked)

### Added

- Idiomatic `.into()` conversions for `Dynamic<T>`

## [0.5.5] - 2025-08-10 (yanked)

### Changed

- Renamed `view()`/`view_mut()` → `expose_secret()`/`expose_secret_mut()`

## [0.5.4] - 2025-11-23 (yanked)

### Added

- `AsRef<[u8]>` / `AsMut<[u8]>` for `Fixed<[u8; N]>`

## [0.5.3] - 2025-11-24 (yanked)

### Changed

- Documentation polish
- Fixed relative changelog link

## [0.5.2] - 2025-11-24 (yanked)

### Added

- Idiomatic `From` / `.into()` for `fixed_alias!` types

### Changed

- Removed inherent impls from macro (now generic)

## [0.5.1] - 2025-11-23 (yanked)

### Added

- `secure!`, `secure_zeroizing!`, `fixed_alias!`, `dynamic_alias!` macros
- `from_slice()` and `From<[u8; N]>` on aliases
- `finish_mut()` emphasis
- Macro test suite

### Changed

- `fixed_alias!` emits only alias; methods via generic impls

### Fixed

- README accuracy on zeroize
- Orphan rule violations
- Privacy/feature-gating

## [0.5.0] - 2025-11-22 (yanked)

### Breaking Changes

- Replaced `SecureGate<T>` with `Fixed<T>` and `Dynamic<T>`
- Removed `ZeroizeMode`, manual wiping, password specializations, `unsafe-wipe`

### Added

- Zero-cost fixed-size secrets
- `Deref`/`DerefMut` ergonomics
- Macros for constructors/aliases
- `into_inner()`, `finish_mut()`
- `Clone` for `Dynamic<T>`

### Fixed

- No unsafe when zeroize off
- Full spare-capacity wipe
- Consistent API

### Improved

- Modular structure
- Unit tests

## [0.4.3] - 2025-11-20 (yanked)

### Fixed

- Documentation mismatch

## [0.4.1] - 2025-11-20 (yanked)

### Added

- Configurable `ZeroizeMode` enum
- New constructors with modes

### Changed

- Unified zeroization through `Wipable` trait

### Fixed

- Full wiping for empty allocated vectors
- Clone preserves mode

## [0.4.0] - 2025-11-20 (yanked)

### Breaking Changes

- Unified under `SecureGate<T>`

### Added

- `SG<T>` alias
- `Zeroizing` for fixed-size

### Deprecated

- Old names

## [0.3.4] - 2025-11-18 (yanked)

### Documentation

- Updated README

## [0.3.3] - 2025-11-18 (yanked)

### Added

- Direct exposure methods on password types

## [0.3.1] - 2025-11-17 (yanked)

### Changed

- Renamed `SecurePasswordMut` → `SecurePasswordBuilder`

## [0.3.0] - 2025-11-13 (yanked)

- Initial public release
