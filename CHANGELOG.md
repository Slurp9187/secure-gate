# Changelog

All changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), 
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-01-25

### Added

- **Polymorphic access traits**
  `ExposeSecret` and `ExposeSecretMut` traits provide generic, zero-cost access with metadata (`len()`, `is_empty()`) without exposing contents. Implemented for both `Dynamic<T>` and `Fixed<T>`.

- **Timing-safe equality**
  `ConstantTimeEq` trait (`ct-eq` feature) with `.ct_eq()` methods on `Fixed<[u8; N]>` and `Dynamic<T: AsRef<[u8]>>`.

- **Fast probabilistic equality for large secrets**
  `ConstantTimeEqExt` trait (requires `ct-eq-hash` feature) extends `ConstantTimeEq` with methods for fast probabilistic equality using BLAKE3 hashing. Includes `ct_eq_hash()` for direct hash comparison and `ct_eq_opt()` for smart hybrid selection between strict equality (small inputs) and hash equality (large inputs). Centralized threshold logic with default 32-byte crossover point. Enhanced documentation with security warnings for probabilistic methods and keyed mode when `rand` feature is enabled.

- **Configurable decode priority in `try_decode_any`**
  Added optional `priority: Option<&[Format]>` parameter to `try_decode_any` for customizable decode order (e.g., strict protocols can enforce single formats like only Hex). Backward compatible with default order (Bech32 → Hex → Base64url).

- **Enhanced decoding errors with hints**
  `DecodingError` variants now include hints (e.g., attempted formats) for better debugging of failed decodes, while allowing production redaction to avoid metadata leaks.

- **Per-format encoding/decoding traits**
  Symmetric, orthogonal traits (e.g., `ToHex`/`FromHexStr`, `ToBase64Url`/`FromBase64UrlStr`, `ToBech32`/`FromBech32Str`, `ToBech32m`/`FromBech32mStr`). Umbrella traits `SecureEncoding`/`SecureDecoding` for aggregation. Multi-format auto-decoding (`try_decode_any`). Granular features: `encoding-hex`, `encoding-base64`, `encoding-bech32`.

- **Opt-in cloning & serialization**
  New marker traits `CloneableType` and `SerializableType`. Cloning and serde serialization now require explicit impls on the inner type — no automatic risk.

- **Secure random generation**
  `from_random()` on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` using `OsRng` (panics on failure).

- **Fallible fixed-size construction**
  `TryFrom<&[u8]>` for `Fixed<[u8; N]>` with `FromSliceError` (safe alternative to panicking conversions).

- **Centralized errors**
  Unified error types (`Bech32Error`, `DecodingError`, `FromSliceError`) via `thiserror`.

- **Additional alias macros**
  `dynamic_generic_alias!` and `fixed_generic_alias!` for generic (const-sized) aliases with optional custom documentation.

- **Testing & CI**
  `trybuild` compile-fail tests, serde fuzz target, expanded CI matrix covering all feature combinations.

- **Documentation**
  New `SECURITY.md`, enhanced README, custom rustdoc for alias macros.

### Changed

- **Secure-by-default exposure model**
  Private `inner` fields in `Dynamic<T>` and `Fixed<T>`; all access now requires explicit `.expose_secret()` / `.with_secret()` (scoped, recommended) or `.expose_secret_mut()` / `.with_secret_mut()`. No `Deref`, `AsRef`, or implicit borrowing — prevents accidental leaks.

- **Bech32 encoding**
  Now fallible (`try_to_bech32` / `try_to_bech32m`); no panics on invalid HRP/data. Strict variant differentiation.

### Changed (Breaking)

- **Default features**
  Now `secure` meta-feature (`zeroize` + `ct-eq`). `full` includes `secure` + `encoding` + `ct-eq-hash` + `cloneable` + `serde` + `rand`. Added `insecure` for explicit opt-out (testing/low-resource only — strongly discouraged).

- **Cloning**
  Removed implicit `Clone` on wrappers; now opt-in via `CloneableType` marker on inner type.

- **Serialization**
  Split `serde` into `serde-deserialize` (always available) and `serde-serialize` (gated by `SerializableType` marker).

- **Exposure API**
  Removed any implicit borrowing paths. All access now explicit.

- **Encoding API refactor: per-format orthogonal traits**
  Removed monolithic `SecureEncoding` trait (clean slate). Introduced symmetric per-format traits: `ToHex`/`FromHexStr`, `ToBase64Url`/`FromBase64UrlStr`, `ToBech32`/`FromBech32Str`, `ToBech32m`/`FromBech32mStr`. Umbrella traits `SecureEncoding`/`SecureDecoding` (feature-gated). Added `try_decode_any` for multi-format auto-decoding. Bech32/BIP-173 & Bech32m/BIP-350 now distinct.

- **Equality traits refactor**
  Renamed `HashEq` trait to `ConstantTimeEqExt` (extends `ConstantTimeEq`). Renamed feature `hash-eq` to `ct-eq-hash`. Methods renamed: `hash_eq` to `ct_eq_hash`, `hash_eq_opt` to `ct_eq_opt` with centralized logic in default impl. Enhanced documentation and warnings.

- **Error handling**
  Unified and renamed error types; removed panicking fallbacks.

### Migration (Encoding Refactor)
- Bounds: `T: SecureEncoding` → same (umbrella) or explicit `T: ToHex + …`
- Calls: `.to_hex()` → same via blanket impl; `.to_bech32(hrp)` → same
- Decoding: use `str.try_from_hex()?` / `try_decode_any()?` for auto-decoding

### Fixed
- Improved Bech32/BIP-173 & Bech32m/BIP-350 variant/HRP handling
- Proper `Display`/`Error` impls for custom errors
- Strict format validation in per-format traits (rejects invalid checksums/variants)

### Removed
- Implicit `Clone` and `Serialize` on wrappers
- Panicking `from_slice` and `new_boxed` methods
- Old encoding helpers (`RandomHex`, etc.)
- Conditional `unsafe` blocks (now unconditionally forbidden)

## [0.6.1] - 2025-12-07

### Security

- **Removed `into_inner()` from `Fixed<T>`, `Dynamic<T>`, `FixedNoClone<T>`, and `DynamicNoClone<T>`**: This closes a security bypass that allowed extracting raw values without going through `expose_secret()` or `expose_secret_mut()`. All access to secret data must now be explicit and auditable through the security gate. When the `zeroize` feature is enabled, this also prevents bypassing `ZeroizeOnDrop` guarantees.
  - **Migration**: Replace `value.into_inner()` with `value.expose_secret()` or `value.expose_secret_mut()` as appropriate.
  - **Note**: `into_inner()` remains available on `FixedRng<N>` and `DynamicRng` as they return secure wrapper types (`Fixed`/`Dynamic`), not raw values. This is a type conversion, not a security escape.
- **Removed `finish_mut()` from `Dynamic<String>`, `Dynamic<Vec<T>>`, `DynamicNoClone<String>`, and `DynamicNoClone<Vec<T>>`**: These methods returned `&mut T` directly, bypassing the `expose_secret_mut()` security gate. This violates the core security principle that all secret access must be explicit and auditable.
  - **Migration**: Replace `secret.finish_mut()` with `secret.expose_secret_mut().shrink_to_fit()` to achieve the same functionality while maintaining security guarantees.

### Added

- **Ergonomic RNG conversions**: `FixedRng<N>` and `DynamicRng` can now be converted to `Fixed` and `Dynamic` via `.into()` or `.into_inner()`
  ```rust
  let key: Fixed<[u8; 32]> = FixedRng::<32>::generate().into();
  let random: Dynamic<Vec<u8>> = DynamicRng::generate(64).into();
  ```
- **Convenience random generation methods**: Direct generation methods on `Fixed` and `Dynamic` for ergonomic random secret creation
  ```rust
  let key: Fixed<[u8; 32]> = Fixed::generate_random();
  let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
  ```

### Changed

- **Macro visibility syntax**: All type alias macros (`fixed_alias!`, `fixed_alias_rng!`, `dynamic_alias!`, etc.) now require explicit visibility specification in line with standard Rust semantics. The automatic `pub` fallback has been removed.

### Before

```rust
fixed_alias!(MyKey, 32);  // Automatically public (implicit behavior)
```

### After

```rust
fixed_alias!(pub MyKey, 32);          // Public type (explicit)
fixed_alias!(MyPrivateKey, 32);       // Private type (no visibility modifier)
fixed_alias!(pub(crate) Internal, 64); // Crate-visible type
```

### Fixed

- **Macro recursion**: Removed unnecessary recursive call in `dynamic_generic_alias!` macro, making it consistent with `fixed_generic_alias!` pattern

### Why

- Improves consistency with Rust's explicit visibility philosophy
- Eliminates surprising automatic behavior in macros
- Makes type visibility intentions clear and auditable
- Removes redundant macro branches, simplifying implementation
- Provides ergonomic conversion paths while preserving type-level security guarantees
- **Enforces the core security principle**: All secret access must be explicit, grep-able, and auditable through `expose_secret()` or `expose_secret_mut()`

### Migration

- Update macro invocations to explicitly specify visibility where needed. Add `pub` for types that should be publicly accessible.
- Replace any `into_inner()` calls on `Fixed<T>`, `Dynamic<T>`, `FixedNoClone<T>`, or `DynamicNoClone<T>` with `expose_secret()` or `expose_secret_mut()`.
- Replace any `finish_mut()` calls on `Dynamic<String>`, `Dynamic<Vec<T>>`, `DynamicNoClone<String>`, or `DynamicNoClone<Vec<T>>` with `expose_secret_mut().shrink_to_fit()`.

## [0.6.0] - 2025-12-06

### Breaking Changes

- Removed `Deref`/`DerefMut` from `Fixed<T>`.
- Made the inner field of `Fixed<T>` private.
- Removed inherent conversion methods (`.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, `.ct_eq()`) from `Fixed<[u8; N]>` and aliases.
- Implemented `SecureConversionsExt` only on raw `[u8]` and `[u8; N]`, requiring explicit `.expose_secret()` for conversions.
- Removed deprecated direct-conversion shims from 0.5.x.
- Replaced `RandomBytes<N>` with `FixedRng<N>`, a newtype over `Fixed<[u8; N]>`.
- Removed `serde` feature; serialization requires user implementation.
- Switched RNG to direct `rand::rngs::OsRng` usage, removing `thread_local!` and `RefCell`.
- Removed all dependancies on `secrecy` as they were no longer necessary.

### Added

- `len()` and `is_empty()` on `Fixed<[u8; N]>`.

- Compile-time negative impl guard for `SecureConversionsExt` on wrapper types.
- `rand_core = { version = "0.9", optional = true }` dependency for `rand` feature.
- Direct `OsRng` calls in `FixedRng<N>::generate()` and `DynamicRng::generate()`.

### Fixed

- Lifetime issue in `FixedRng::<N>::random_hex()`.
- `ct_eq` bounds on fixed-size arrays, using `.as_slice()`.
- Updated tests and benchmarks to explicit `.expose_secret()`.
- Internal cleanups and dead code removal.

### Performance

- Benchmarks show `Fixed<[u8; 32]> + .expose_secret()` indistinguishable from raw `[u8; 32]` access on Intel i7-10510U (2019).
- Direct `OsRng` usage increases key generation throughput by 8–10% over prior `thread_local!` implementation.

## [0.5.10] - 2025-12-02

### Added

- `HexString` newtype in `conversions.rs` for type-safe, validated hex strings (requires "conversions" feature). Includes `.new()` with validation (even length, ascii hex digits, lowercase normalization), `.to_bytes()` for safe decoding, and `.byte_len()` property. Enforces `.expose_secret()` for access, aligning with safety rules.
- `RandomHex` newtype in `conversions.rs` for random hex strings (requires "rand + conversions"). Wraps `HexString`, inherits methods like `.to_bytes()` via Deref, enforces `.expose_secret()`. Constructor only via RNG for freshness.
- `PartialEq` and `Eq` impls for `Dynamic<T>` (bounded on T: PartialEq/Eq) in `dynamic.rs`—enables comparisons on dynamic secrets like `Dynamic<String>`.
- `RandomBytes<const N: usize>` newtype in `rng.rs` for semantically fresh random bytes (requires "rand" feature). Wraps `Fixed<[u8; N]>`, inherits methods via Deref, enforces `.expose_secret()`/`.expose_secret_mut()`.
- `random_alias!` macro in `macros.rs` for aliases on `RandomBytes<N>` (requires "rand" feature). Syntax: `random_alias!(Name, size);`—inherits `.new()` and deprecated shims; supports `.random_hex()` if "conversions" enabled.
- Comprehensive paranoia tests: `macros_paranoia_tests.rs` (all macros + edges) and `random_bytes_paranoia_tests.rs` (RandomBytes safety, deprecations, type distinctions).

### Changed

- Renamed randomness method to `.new()` in `rng.rs` for idiomatic constructors (Clippy-compliant). Added soft deprecations for `.random_bytes()` and `.random()` with friendly notes and doc aliases.
- Updated doc examples in `lib.rs` and `rng.rs` to use `random_alias!` and `.new()`.

### Fixed

- Privacy/import issues in tests (e.g., `use secure_gate::rng::{RandomBytes, SecureRandomExt};`).
- Doc-test failures by adding trait imports in examples.
- Test assertions in paranoia suites (e.g., expect different random values, not equal).
- Macro expansion/orphan rules by moving trait impls to `rng.rs` generics.
- Zeroize access in tests via `secrecy::ExposeSecret`.

## [0.5.9] - 2025-11-30

### Security & API Improvement — `conversions` feature

- **All conversion methods now require explicit `.expose_secret()`** 
  This is a deliberate breaking change to restore the crate’s core security invariant: 
  every access to secret bytes must be loud, visible, and grep-able.

  ```rust
  // v0.5.8 (deprecated)
  let hex = key.to_hex();

  // v0.5.9+ (required)
  let hex = key.expose_secret().to_hex();
  ```

  The same applies to `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()`.

- Direct methods on `Fixed<[u8; N]>` are **deprecated** and will be removed in v0.6.0.
- Old syntax continues to work with clear deprecation warnings.
- Compile-time test added: removing any `#[deprecated]` attribute now **fails CI**.
- Documentation and examples fully updated to teach the safe pattern.

This change eliminates a subtle but serious footgun while preserving ergonomics and backward compatibility during the 0.5.x series.

## [0.5.8] - 2025-11-29

### Added

- **New optional `conversions` feature** — the most requested ergonomics upgrade yet!
  - Adds `.to_hex()`, `.to_hex_upper()`, `.to_base64url()`, and `.ct_eq()` to **all** `Fixed<[u8; N]>` types and `fixed_alias!` types
  - Enabled with `features = ["conversions"]`
  - **Zero impact** on minimal or `no_std` builds — only compiled when requested
  - Perfect for:
    - Exporting keys to JSON (`to_base64url()`)
    - Logging/debugging (`to_hex()` with redacted `Debug`)
    - Secure equality checks (`ct_eq()` — timing-attack resistant)
  - Fully tested with real vectors and constant-time verification
  - Named consistently with `SecureRandomExt` → `SecureConversionsExt`

````rust
fixed_alias!(FileKey, 32);
let key = FileKey::random();
let password = Password::new(key.to_hex());        // beautiful
let export = key.to_base64url();                   // safe for JSON
assert!(key.ct_eq(&other_key));                    // secure

## [0.5.7] - 2025-11-27

### Added
- **New `rand` feature**: `SecureRandomExt::random()` for all `Fixed<[u8; N]>` and `fixed_alias!` types (#18)
  ```rust
  fixed_alias!(Aes256Key, 32);
  fixed_alias!(XChaCha20Nonce, 24);

  let key = Aes256Key::random();       // zero-cost, cryptographically secure
  let nonce = XChaCha20Nonce::random();
````

- Powered by thread-local `rand::rngs::OsRng` (lazy initialization)
- Uses modern `TryRngCore::try_fill_bytes` (rand 0.9+)
- No heap allocation, fully safe, `no_std`-compatible
- Panics on RNG failure (standard for high-assurance crypto code)
- Fully tested and Clippy-clean

### Documentation

- **Complete rustdoc overhaul** (#14)
  - Every public item now has clear, consistent, and fully-tested documentation
  - All examples compile under `--all-features` and `--no-default-features`
  - Added comprehensive module overviews, tables, security rationales, and idiomatic usage patterns
  - 100% passing `cargo test --doc`
  - Fixed all Clippy doc lint warnings

## [0.5.6] - 2025-04-05

### Added

- **Major ergonomics upgrade** – `Dynamic<T>` and `DynamicZeroizing<T>` now implement idiomatic `.into()` conversions:

  ```rust
  dynamic_alias!(Password, String);
  dynamic_alias!(JwtKey, Vec<u8>);

  // The dream syntax – just works!
  let pw: Password = "hunter2".into();                     // From<&str>
  let pw: Password = "hunter2".to_string().into();         // From<String>
  let key: JwtKey = secret_bytes.into();                   // From<Vec<u8>>

  // Zeroizing variants too!
  let pw: DynamicZeroizing<String> = "temp secret".into();
  let key: DynamicZeroizing<Vec<u8>> = vec![0u8; 32].into();
  ```

## [0.5.5] - 2025-08-10

### Changed

- **API: `view()` / `view_mut()` → `expose_secret()` / `expose_secret_mut()`**
  The old `.view()` and `.view_mut()` methods are now **deprecated** and forward directly to the new canonical API:

  ```rust
  // Old (deprecated in 0.5.5, removed in 0.6.0)
  key.view()           // → &T
  key.view_mut()       // → &mut T

  // New — recommended
  key.expose_secret()      // → &T
  key.expose_secret_mut()  // → &mut T
  ```

## [0.5.4] - 2025-11-23

### Added

- `AsRef<[u8]>` and `AsMut<[u8]>` implementations for `Fixed<[u8; N]>`, enabling seamless integration with crates expecting slice references (e.g., cryptographic libraries like `aes` or `chacha20poly1305`). (Closes #13)

## [0.5.3] - 2025-11-24

### Changed

- Documentation polish & real-world proof
  - Added live Criterion benchmark report showing **zero overhead** on real hardware
  - Updated all examples and links to reflect final v0.5.x API
  - Changelog link now absolute (fixes broken link on docs.rs)

### Fixed

- Relative `CHANGELOG.md` link in README now points to the correct file on GitHub

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
