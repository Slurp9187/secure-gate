# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **Renamed `ExposeSecret` → `RevealSecret` and `ExposeSecretMut` → `RevealSecretMut` (#101)** — The two core access traits have been renamed. `RevealSecret` more accurately describes the capability ("this type supports controlled revelation of its secret contents") while keeping `expose_secret` / `expose_secret_mut` as method names preserves their warning tone for the escape-hatch paths. All method names (`with_secret`, `with_secret_mut`, `expose_secret`, `expose_secret_mut`) and all struct/macro/encoding API surfaces are **unchanged**. Only code that names the trait explicitly is affected: `use secure_gate::ExposeSecret` → `use secure_gate::RevealSecret`; `T: ExposeSecret` bounds → `T: RevealSecret`; same for the `Mut` variant. Users who only call methods via method resolution are unaffected.

- **HRP-primary Bech32/Bech32m APIs (#100)** — `FromBech32Str` / `FromBech32mStr`: primary decode is now `try_from_bech32(expected_hrp)` / `try_from_bech32m(expected_hrp)` (payload only); raw `(HRP, bytes)` is `try_from_bech32_unchecked` / `try_from_bech32m_unchecked`. `ToBech32` / `ToBech32m`: `try_to_bech32(hrp)` / `try_to_bech32m(hrp)` only (removed optional second HRP). `Fixed` / `Dynamic`: `try_from_bech32(s, hrp)` / `try_from_bech32m(s, hrp)` for validated decode; `try_from_bech32_unchecked` / `try_from_bech32m_unchecked` replace the old single-arg `try_from_bech32` / `try_from_bech32m`. Migrate: `"s".try_from_bech32()` → `try_from_bech32_unchecked()`; `try_from_bech32_with_hrp(hrp)` → `try_from_bech32(hrp)`; `try_to_bech32(hrp, None)` → `try_to_bech32(hrp)`; wrappers: `try_from_bech32_with_hrp(s, hrp)` → `try_from_bech32(s, hrp)`, `try_from_bech32(s)` → `try_from_bech32_unchecked(s)` (and Bech32m analogs).
- **Removed `ToHex::to_hex_left`** — the redacted-logging helper has been removed from the `ToHex` trait. The function allocated a full hex-encoded `String` of the entire secret and dropped it without zeroization on the truncation path, contradicting its intended "safe for logs" purpose. Callers should construct any redacted output according to their own threat model (e.g. `format!("{}…", &hex[..n])` wrapped in `zeroize::Zeroizing`).
- **Removed `ct-eq-hash` feature** — `ConstantTimeEqExt`, `ct_eq_hash`, `ct_eq_auto`, optional `blake3` and `once_cell` dependencies, `CT_EQ_AUTO.md`, and related benches/tests/fuzz targets are gone. Timing-safe equality is only [`ConstantTimeEq::ct_eq`](https://docs.rs/secure-gate/latest/secure_gate/trait.ConstantTimeEq.html) (`ct-eq`). Migrate: enable `ct-eq` and replace any `ct_eq_hash` / `ct_eq_auto` usage with `.ct_eq()`.
- **Renamed `_expect_hrp` Bech32 constructors to `_with_hrp`** — `Fixed::try_from_bech32_expect_hrp`, `Fixed::try_from_bech32m_expect_hrp`, `Dynamic::try_from_bech32_expect_hrp`, and `Dynamic::try_from_bech32m_expect_hrp` are now `try_from_bech32_with_hrp` / `try_from_bech32m_with_hrp`. The `_with_hrp` naming follows idiomatic Rust conventions (`with_capacity`, `with_header`, etc.) and avoids implying a panic on mismatch. Migrate: rename call sites; the method signatures and behavior are identical.

### Security

- **Serde visitor length error now redacted in release builds** (`src/fixed.rs`) — `serde::de::Error::invalid_length(vec.len(), ...)` embedded the actual received byte count unconditionally, inconsistent with every other length-revealing error in the codebase. In release builds the error is now `serde::de::Error::custom("decoded length mismatch")`; debug builds retain the detailed form for diagnostics.
- `Dynamic<Vec<u8>>` decoding constructors (`try_from_hex`, `try_from_base64url`, `try_from_bech32`, `try_from_bech32_with_hrp`, `try_from_bech32m`, `try_from_bech32m_with_hrp`) and `Deserialize` now route decoded bytes through a `Zeroizing` wrapper before passing them to `Self::new`, matching the existing pattern in `Fixed<T>`. Uses `core::mem::take` — zero extra heap allocation. (#96)
- `Dynamic<String>` `Deserialize` now wraps the intermediate `String` in `Zeroizing` before construction, matching `Dynamic<Vec<u8>>` and `Fixed<T>`. (#97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization now reject inputs exceeding `MAX_DESERIALIZE_BYTES` (1 MiB by default). Oversized buffers are zeroized before rejection. `deserialize_with_limit` is available for custom ceilings. (#99)
- **`Fixed<T>` decoding stack residue documented** (`SECURITY.md`) — the `try_from_hex`, `try_from_base64url`, and related decoding constructors on `Fixed<[u8; N]>` use `copy_from_slice` into a stack-allocated `[0u8; N]` before moving the array into the wrapper. The intermediate stack slot is not explicitly zeroed before the move; in adversarial environments (core dumps, memory forensics) secret bytes may persist briefly on the stack. The compiler often eliminates the slot entirely in release mode. `Dynamic<T>` avoids this pattern via `protect_decode_result` + `mem::take` (heap-only path). Documented in `SECURITY.md` under Wrappers potential weaknesses.

### Added

- **`rust-version = "1.75"` in `Cargo.toml`** — documents the crate's MSRV. Rust 1.75 (October 2023) is the realistic floor for the current proc-macro dependency tree (`syn` 2.x, `unicode-ident`, `thiserror` 2.x all require ≥ 1.71–1.75) and provides approximately 2.5 years of toolchain coverage.
- **HRP-validating wrapper constructors** — `Fixed::try_from_bech32_with_hrp(s, hrp)`, `Fixed::try_from_bech32m_with_hrp(s, hrp)`, `Dynamic::try_from_bech32_with_hrp(s, hrp)`, and `Dynamic::try_from_bech32m_with_hrp(s, hrp)`. These enforce case-insensitive HRP matching at the wrapper level, returning `Bech32Error::UnexpectedHrp` on mismatch. The existing HRP-discarding constructors are retained but now carry a `# Warning` doc note directing security-critical callers to the `_with_hrp` variants.
- **`Dynamic<String>` allocator-level zeroization oracle** (`tests/heap_zeroize.rs`) — `check_string_zeroed` helper mirrors `check_vec_zeroed` and verifies via `ProxyAllocator` that the `String` backing buffer is fully zeroed before deallocation. Called at sizes 16 and 32 from the aggregate `all_heap_zeroed` test.
- **Generic macro test coverage** (`tests/macros_suite/fixed_generic.rs`, `tests/macros_suite/dynamic_generic.rs`) — exercises `fixed_generic_alias!` (basic instantiation at N=16/32, `size_of` check, and an explicit N=0 documentation test showing the absence of a compile-time guard) and `dynamic_generic_alias!` (Vec<u8> and String instantiation). `tests/macros_suite/mod.rs` updated accordingly.
- `std` feature: opt-in full `std` support that implies `alloc`. Use `features = ["std"]` if you need `std`-specific integrations; `alloc` (the default) remains sufficient for all current functionality.
- **Expanded zeroization integration test coverage** (closes #94):
  - `Fixed<[u8; N]>` tested for N = 8, 16, 32, 64, 128 via a parameterized macro; all cases use `core::hint::black_box` to prevent LLVM from eliding the zeroization write.
  - Pre-drop mutation tests for `Fixed<T>`: covers `with_secret_mut`, `expose_secret_mut`, custom `Zeroize` types, and scoped-access-then-drop patterns.
  - `Dynamic<[u8; N]>` heap zeroization verified at the allocator level for N = 16, 32, 64, 128 via `ProxyAllocator`.
  - `Dynamic<Vec<u8>>` backing-buffer zeroization verified for the same sizes with fill → `shrink_to_fit` → drop sequences.
  - Mutation sequence tests for `Dynamic<Vec<u8>>` and `Dynamic<String>` covering `push`, `truncate`, `extend_from_slice`, `shrink_to_fit`, and `with_secret_mut` before drop.
  - Spare-capacity zeroization tests for both `Dynamic<Vec<u8>>` and `Dynamic<String>`.
  - Scoped `with_secret_mut` + drop tests for `Dynamic<Vec<u8>>`.
  - `heap_zeroize.rs` refactored to a single aggregate `#[test]` (`all_heap_zeroed`) eliminating race conditions with the global `ProxyAllocator` state under parallel test execution.
  - All new tests run cleanly under `cargo test --no-default-features`, `cargo test --release --features alloc`, and `cargo +nightly miri test --features alloc`.
- Added ASan CI job (`asan-heap`) for heap zeroization verification using `cargo +nightly test --features alloc --test heap_zeroize -Z build-std`.

### Fixed

- **`rand` feature no longer forces `alloc`** (`Cargo.toml`) — `rand?/alloc` has been removed from the `rand` feature. `Fixed::from_random()` only uses `OsRng::try_fill_bytes` on a stack array and requires no heap allocation; `rand` now works in pure `no_std`/`no_alloc` builds for `Fixed<T>`. `Dynamic::from_random()` continues to work when `alloc` is also active, since `Dynamic<T>` already requires `alloc` independently.
- **`tests/heap_zeroize.rs` hardened against silent false negatives and gate leakage** — test-only improvements, no library behavior changes: (1) `check_vec_zeroed` and `check_string_zeroed` now `assert_eq!(capacity, size)` after `shrink_to_fit` — without this, an allocator that rounds up capacity silently bypasses the proxy check producing a false negative; (2) `with_proxy_check` now uses a `CheckGuard` RAII struct to ensure `CHECKING` is cleared even when the closure panics — previously a panic left the gate open during stack unwinding; (3) all four helper closures now call `drop(secret)` explicitly to make drop timing clear and refactor-safe; (4) `Dynamic<String>` size coverage expanded from 2 to 4 sizes (16/32/64/128) to match `Dynamic<Vec<u8>>`; (5) Vec and String checks now interleaved in a `for size in [16, 32, 64, 128]` loop that structurally enforces size parity.
- **Wrong feature gate on `fixed_deserialize_wrong_length` test** (`tests/serde_suite/deserialize.rs`) — the test was gated `#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]`; hex encoding has no relationship to serde deserialization length checking. Corrected to `#[cfg(feature = "serde-deserialize")]` so the error path (including `Zeroizing<Vec<u8>>` drop on length mismatch) is exercised in minimal serde-only feature configurations.
- **`static` secrets + `panic = "abort"` footguns documented** (`SECURITY.md`) — `Fixed::new` is `const fn`, so `static SECRET: Fixed<...> = Fixed::new([...])` compiles silently but is never zeroized (Rust does not invoke `Drop` on program-scope statics). Additionally, `panic = "abort"` builds skip all `Drop` impls on panic, meaning secrets in scope at the time of a panic are not cleared. Both limitations are shared by the broader `zeroize` / `secrecy` ecosystem; they are now documented under _Wrappers — Potential weaknesses_ with concrete mitigation notes.
- **MSRV CI job** (`.github/workflows/ci.yml`) — runs `cargo +1.75 check` with default features and with `--features=full` on every push and PR. Previously, `full` was excluded from MSRV because `ct-eq-hash` pulled in `blake3` → `constant_time_eq` (edition2024). That feature has been removed.
- **Weak-dependency feature syntax throughout `Cargo.toml`** — every feature entry of the form `pkg/feature` where `pkg` is an optional dependency declared with `dep:` syntax has been changed to `pkg?/feature`. Without `?`, Cargo rejects the activation on MSRV toolchains because the optional dep has no implicit feature name. Affected entries: `rand?/alloc`, `hex?/alloc`, `base64?/alloc`, `bech32?/alloc`, `serde?/alloc`. The non-optional `zeroize/alloc` is unaffected.

### Changed

- **Encoding exposure model documented** (`README.md`, `SECURITY.md`, `src/traits/encoding/`) — `README.md` Encoding section rewritten to match the Equality section's upfront bullet style: three access patterns (direct method, `with_secret` closure, `expose_secret` escape hatch) with security trade-offs and audit-greppability callouts; full method reference table with fallible column and `_with_hrp` preference for Bech32; consolidated audit grep command; decode-side wrap-immediately note. Stale/incorrect "must call `expose_secret` first" claim removed from `base64_url.rs` module doc. "Audit visibility" security note added to `hex.rs`, `bech32.rs`, and `bech32m.rs`. `SECURITY.md` Encoding/Decoding mitigations block updated with exposure contract and audit grep caveat.
- **Proptest case counts raised to 256 with boundary strategies** (`tests/proptest_suite/`) — all `ProptestConfig::with_cases` overrides raised from 30/50 to 256. Variable-length vector arguments in `ct_eq_symmetric`, `dynamic_hex_roundtrip`, `dynamic_b64_roundtrip`, and `serializable_vec_roundtrip` now use `prop_oneof!` to guarantee empty, single-byte, and max-size inputs on every run rather than relying on random chance to hit them.
- **`serializable_secret_misuse` compile-fail test re-enabled** (`tests/compile_fail_tests.rs`, `tests/compile-fail/`) — the test was commented out due to a stale `.stderr` snapshot referencing `zeroize::DefaultIsZeroes` (removed in v0.8.0) and because `BadSecret` lacked a `Zeroize` impl, causing the compile error to land at `Dynamic::new()` rather than at `serde_json::to_string()`. Fixed by deriving `Zeroize` on `BadSecret` so construction succeeds and the error is correctly about `SerializableSecret` not being satisfied — the intended security boundary. Snapshot regenerated; test re-enabled with `#[cfg(not(miri))]` (same pattern as the sibling `fixed_alias_zero_size_compile_fail` test).
- **`fixed_generic_alias!` implementation notes rewritten** (`src/macros/fixed_generic_alias.rs`) — the previous note inaccurately referred to "a compile-time zero-size guard inherited from `Fixed<[u8; N]>`" that does not exist for generic aliases. The note now explains that `N=0` cannot be rejected at macro-invocation time (unlike `fixed_alias!`), that `SecretBuffer::<0>` compiles to a zero-byte type with no cryptographic utility, and directs callers to validate `N > 0` in their own tests.
- **`partial_eq_fallback` test renamed** (`tests/ct_eq_suite/basic.rs`) — renamed to `manual_comparison_without_ct_eq_feature` and given an explicit comment warning that the comparison is non-constant-time and that `ct-eq` + `ConstantTimeEq` should be used for security-sensitive equality.
- **`Bech32Error::ConversionFailed` documented as currently unreachable** (`src/error.rs`) — the variant is never produced: `.byte_iter()` on a successfully-validated `CheckedHrpstring` is infallible in the `bech32` crate; any bit-conversion failure surfaces as `OperationFailed` during the `CheckedHrpstring::new()` call. The variant is retained as public API for forward compatibility.
- **`Bech32Large` capacity documentation corrected** — all inline docs stated "~3.2 KB raw data"; the correct figure is ~5 KB (5,115 bytes maximum payload). Updated in `src/traits/encoding/bech32.rs`, `src/traits/encoding/bech32m.rs`, and `src/traits/decoding/bech32.rs`.
- **README serde section scoped** — the "no temporary string buffers" claim now explicitly excludes `Dynamic<String>`, which delegates deserialization to serde internals that may allocate non-zeroized intermediate buffers. `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` retain the guarantee. This scoping was subsequently resolved: `Dynamic<String>` deserialization now wraps its buffer in `Zeroizing` (#97), so the limitation no longer applies.
- **`cloneable_secret_works` extended** (`tests/core_tests.rs`) — wrapper-level `Fixed<CloneKey>` clone independence test added: creates a `Fixed<CloneKey>`, clones it, drops the original (triggering zeroization of its `Vec<u8>` backing), and drops the clone. Both sequential drops succeeding without panic proves the clone owns independent heap memory.
- **`try_from_bech32` / `try_from_bech32m` constructors now document HRP discard** — existing `Fixed` and `Dynamic` wrapper constructors carry a `# Warning` doc note directing security-critical callers to the HRP-validating variants (then named `_expect_hrp`, now renamed to `_with_hrp`).
- Version bump from 0.8.0-alpha.1 to 0.8.0-rc.1.
- **Breaking**: The `no-alloc` feature has been removed. To build without heap allocation (`Fixed<T>` only, embedded / pure `no_std`), use `default-features = false`. This matches the idiomatic Rust pattern used by `zeroize`, `serde`, `rand`, and others.
- The `compile_error!` guard that prevented `alloc` and `no-alloc` from being enabled simultaneously has been removed along with `no-alloc`.
- `heap_zeroize.rs` tests are skipped under Miri (`#![cfg(not(miri))]`) due to fundamental incompatibility between `#[global_allocator]` and Miri's Stacked Borrows model; heap zeroization is still verified in normal CI and under ASan.
- `compile_fail_tests.rs` trybuild test is skipped under Miri (`#[cfg(not(miri))]`) since compile-fail diagnostics are not relevant to runtime UB detection.

### Migration

```toml
# Before (0.8.0-alpha.1)
secure-gate = { version = "0.8", default-features = false, features = ["no-alloc"] }

# After
secure-gate = { version = "0.8", default-features = false }
```

```rust
// ct-eq-hash removal (if you used the old feature)
// Before
// secret_a.ct_eq_hash(&secret_b);  // or ct_eq_auto(...)
// After — enable `ct-eq` and use deterministic comparison:
secret_a.ct_eq(&secret_b);
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
- `**tests/common.rs`\*\*: shared helper module with `assert_redacted_debug` and
  `RevealSecret`/`RevealSecretMut` re-exports available to all suite sub-modules.
- **Bech32/Bech32m error-path test coverage** (`tests/encoding_suite/bech32.rs`): six new
  tests trigger actual `Bech32Error` variants through encode/decode calls — invalid HRP
  encoding, malformed string decoding, and decode-side HRP validation (happy path and
  mismatch) for both `bech32` and `bech32m`.
- **Fuzz targets**: new `fuzz/fuzz_targets/encoding.rs`, `serde.rs`, and `ct_eq.rs` covering
  encoding round-trips for all four formats, serde serialize/deserialize, and constant-time
  equality. Expanded `expose.rs`, `mut.rs`, `parsing.rs`, and `fuzz/src/arbitrary.rs`.

### Fixed

- Updated trybuild snapshots to resolve CI mismatches for all feature configurations.
- `**benches/ct_eq_auto.rs`\*\*: Wrapped all inputs outside `iter` in `std::hint::black_box()` to prevent constant-folding (matches fix already applied in `fixed_vs_raw.rs`). Corrected four inverted benchmark names where `_force_ct_eq`/`_force_hash` labels contradicted the actual threshold path taken (`ct_eq_auto` selects `ct_eq` when `len ≤ threshold`, `ct_eq_hash` when `len > threshold`). Collapsed duplicate `criterion_main!` pair into a single `#[cfg(feature = "ct-eq-hash")]` call.
- `**benches/ct_eq_hash_vs_standard.rs**`: Same `black_box()` fix on inputs. Added missing top-level imports (`ConstantTimeEq`, `ConstantTimeEqExt`, `Fixed`, `Dynamic`) — the bench previously failed to compile under `--features ct-eq-hash,alloc,rand`. Removed a redundant outer `#[cfg(feature = "ct-eq-hash")]` wrapping an already-specific inner `#[cfg(all(...))]`; collapsed duplicate `criterion_main!`.
- `**benches/serde.rs**`: Removed unused `extern crate alloc;` and corrected run command to `--features serde`. Added `#[derive(zeroize::Zeroize)]` to the local helper types (`SerializableArray32`, `SerializableVec`, `SerializableString`) — without it they could not be wrapped in `Fixed<T>`/`Dynamic<T>` (both require `T: Zeroize`), so the bench never exercised wrapper serialization at all. Added `Fixed<SerializableArray32>`, `Dynamic<SerializableVec>`, and `Dynamic<SerializableString>` serialize benchmarks alongside the existing newtype/raw comparisons, confirming zero-overhead delegation. Consolidated scattered local `use` statements into a single top-level import; fixed `.clone()` calls on non-`Clone` types. Moved 1 MB fixture allocation outside `iter()` so large benchmarks measure serialization rather than alloc + 2 × 1 MB `zeroize-on-drop` per sample.

### Changed

- Zeroization is no longer optional — always enabled and enforced.
- Documentation updated throughout to reflect mandatory zeroize requirement.
- `alloc` feature now enables `zeroize/alloc` for full spare-capacity wiping in `Dynamic<Vec<T>>`/`Dynamic<String>`.
- `**CT_EQ_AUTO.md**`: Refreshed all performance figures from a clean-machine run after the `black_box` fixes. Key corrections: 32 B ratio 1.7× → 2.3× (`ct_eq` ~~127 ns, `ct_eq_hash` ~288 ns); 100 KB figures reflect the permanent increase from `zeroize-on-drop` overhead (~~169 µs vs ~~565 µs, ~3.3×, not the pre-zeroize 6.5×); raw hash overhead corrected to ~59–75 ns; caching note now distinguishes 32 B cache miss (~~6%) from 1 KB alloc+zeroize cost (~70%); threshold crossover confirmed closer to 64 B; outlier ceiling ≤8% → ≤20%.

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
  `RevealSecret` and `RevealSecretMut` traits provide generic, zero-cost access with metadata (`len()`, `is_empty()`) without exposing contents. Implemented for both `Dynamic<T>` and `Fixed<T>`.
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
