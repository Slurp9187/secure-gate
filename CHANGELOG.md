# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0-rc.1] - 2026-03-17

**Release candidate for 0.8.0**

### Added

- `std` feature: opt-in full `std` support that implies `alloc`. Use `features = ["std"]` if you need `std`-specific integrations; `alloc` (the default) remains sufficient for all current functionality.

### Changed

- Version bump from 0.8.0-alpha.1 to 0.8.0-rc.1.
- **Breaking**: The `no-alloc` feature has been removed. To build without heap allocation (`Fixed<T>` only, embedded / pure `no_std`), use `default-features = false`. This matches the idiomatic Rust pattern used by `zeroize`, `serde`, `rand`, and others.
- The `compile_error!` guard that prevented `alloc` and `no-alloc` from being enabled simultaneously has been removed along with `no-alloc`.

### Migration

```toml
# Before (0.8.0-alpha.1)
secure-gate = { version = "0.8", default-features = false, features = ["no-alloc"] }

# After
secure-gate = { version = "0.8", default-features = false }
```

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

- **Test suite reorganized** into domain-based directory suites (`ct_eq_suite/`,
  `encoding_suite/`, `serde_suite/`, `macros_suite/`, `proptest_suite/`) compiled into a
  single `integration` binary. Standalone binaries (`core_tests`, `error_tests`,
  `no_alloc_tests`, `zeroize_tests`, `heap_zeroize`, `compile_fail_tests`) are each
  auto-discovered by `cargo test --tests`. Replaced all old monolithic test files (`tests/codec/`,
  `tests/ct_eq_auto.rs`, `tests/ct_eq_tests.rs`, `tests/proptest_tests.rs`, `tests/serde/`,
  `tests/macros/`, `tests/insecure_tests.rs`).

- **`tests/common.rs`**: shared helper module with `assert_redacted_debug` and
  `ExposeSecret`/`ExposeSecretMut` re-exports available to all suite sub-modules.

- **Bech32/Bech32m error-path test coverage** (`tests/encoding_suite/bech32.rs`): six new
  tests trigger actual `Bech32Error` variants through encode/decode calls — invalid HRP
  encoding, malformed string decoding, and decode-side HRP validation (happy path and
  mismatch) for both `bech32` and `bech32m`.

- **Fuzz targets**: new `fuzz/fuzz_targets/encoding.rs`, `serde.rs`, and `ct_eq.rs` covering
  encoding round-trips for all four formats, serde serialize/deserialize, and constant-time
  equality. Expanded `expose.rs`, `mut.rs`, `parsing.rs`, and `fuzz/src/arbitrary.rs`.

### Fixed

- Updated trybuild snapshots to resolve CI mismatches for all feature configurations.

- **`benches/ct_eq_auto.rs`**: Wrapped all inputs outside `iter` in `std::hint::black_box()` to prevent constant-folding (matches fix already applied in `fixed_vs_raw.rs`). Corrected four inverted benchmark names where `_force_ct_eq`/`_force_hash` labels contradicted the actual threshold path taken (`ct_eq_auto` selects `ct_eq` when `len ≤ threshold`, `ct_eq_hash` when `len > threshold`). Collapsed duplicate `criterion_main!` pair into a single `#[cfg(feature = "ct-eq-hash")]` call.

- **`benches/ct_eq_hash_vs_standard.rs`**: Same `black_box()` fix on inputs. Added missing top-level imports (`ConstantTimeEq`, `ConstantTimeEqExt`, `Fixed`, `Dynamic`) — the bench previously failed to compile under `--features ct-eq-hash,alloc,rand`. Removed a redundant outer `#[cfg(feature = "ct-eq-hash")]` wrapping an already-specific inner `#[cfg(all(...))]`; collapsed duplicate `criterion_main!`.

- **`benches/serde.rs`**: Removed unused `extern crate alloc;` and corrected run command to `--features serde`. Added `#[derive(zeroize::Zeroize)]` to the local helper types (`SerializableArray32`, `SerializableVec`, `SerializableString`) — without it they could not be wrapped in `Fixed<T>`/`Dynamic<T>` (both require `T: Zeroize`), so the bench never exercised wrapper serialization at all. Added `Fixed<SerializableArray32>`, `Dynamic<SerializableVec>`, and `Dynamic<SerializableString>` serialize benchmarks alongside the existing newtype/raw comparisons, confirming zero-overhead delegation. Consolidated scattered local `use` statements into a single top-level import; fixed `.clone()` calls on non-`Clone` types. Moved 1 MB fixture allocation outside `iter()` so large benchmarks measure serialization rather than alloc + 2 × 1 MB `zeroize-on-drop` per sample.

### Changed

- Zeroization is no longer optional — always enabled and enforced.
- Documentation updated throughout to reflect mandatory zeroize requirement.
- `alloc` feature now enables `zeroize/alloc` for full spare-capacity wiping in `Dynamic<Vec<T>>`/`Dynamic<String>`.
- **`CT_EQ_AUTO.md`**: Refreshed all performance figures from a clean-machine run after the `black_box` fixes. Key corrections: 32 B ratio 1.7× → 2.3× (`ct_eq` ~127 ns, `ct_eq_hash` ~288 ns); 100 KB figures reflect the permanent increase from `zeroize-on-drop` overhead (~169 µs vs ~565 µs, ~3.3×, not the pre-zeroize 6.5×); raw hash overhead corrected to ~59–75 ns; caching note now distinguishes 32 B cache miss (~6%) from 1 KB alloc+zeroize cost (~70%); threshold crossover confirmed closer to 64 B; outlier ceiling ≤8% → ≤20%.

### Migration

- Update code to satisfy `T: Zeroize` (most real secrets already do).
- Replace any remaining optional-zeroize assumptions with mandatory behavior.

### CI / Dev

- CI matrix (`ci.yml`, `test_all.sh`) expanded: per-format encoding isolation configs added
  (`encoding-base64`, `encoding-bech32`, `encoding-bech32m`, `encoding-bech32 + bech32m`);
  `alloc` added to all `ct-eq`/`ct-eq-hash` entries so `Dynamic`-backed tests run; `rand`
  label corrected to reflect it always enables `alloc` via its feature graph.
- `fuzz-miri.yml`: `--skip` updated from stale `serde_core_without_marker_compile_fail` to
  `serializable_secret_misuse` (test renamed in refactor); the old name was a silent no-op
  that left the trybuild subprocess test unguarded under Miri.
- `tests/compile_fail_tests.rs`: `serializable_secret_misuse` now gated on
  `#[cfg(all(feature = "alloc", feature = "serde-serialize"))]`; previously triggered
  irrelevant missing-feature diagnostics under `--no-default-features`.

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
