# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0-rc.12] - 2026-09-08

Backport release. Brings `main`'s PRs #171-#174 to the 0.8 LTS line, adapted to this
branch's contract: MSRV 1.70, edition 2021, and its pinned dependencies. Unpublished
release candidate; nothing is pushed to crates.io.

### Changed (breaking, `secure-gate`)

- **Every encoder returns `EncodedSecret`** (#172); the `*_zeroizing` twins are gone, so
  the short name is the safe one. An encoded secret is a second full copy of the secret
  in a longer alphabet, and is now wiped by default.
- **`into_inner` returns the plain value** (#172); `InnerSecret<T>` is deleted.
  Protection ends at that call rather than following the value into the caller.
- **`encoding-bech32m` folded into `encoding-bech32`** (#171). BIP-173 and BIP-350 are
  one dependency, one error type and one code-length knob.
- **Encoders require the new `EncodableBytes` marker** (#172), so string-shaped inputs
  are rejected: `"text".to_hex()` and re-encoding an `EncodedSecret` no longer compile.
- `DecodingError` and `Bech32Error::ConversionFailed` removed (#171).

### Added (`secure-gate`)

- **Caller-chosen bech32 code length** (#171): `try_to_bech32_sized::<N>` and the
  bech32m twin, `Bech32Sized` / `Bech32mSized`, `bech32_code_length`, and
  `BECH32_CODE_LENGTH`. The default stays the BIP-173 bound.

### Fixed

- **`cargo doc` builds on MSRV 1.70 again.** Grouped `pub use` re-exports reintroduced
  the rustdoc 1.70 ICE that `SecretLen` already hit; the three bech32 re-exports are
  split, and a `Rustdoc - builds on MSRV (1.70)` CI job now guards it with
  `-D warnings`. docs.rs builds on nightly and was never affected, which is why nothing
  noticed.
- **A base32 denial-of-service pin was restored.** `base32ct` 0.2 panics on trailing
  block lengths of 1, 3 or 6 characters; the guard is live in `src/`, but the test
  parity pass had briefly dropped its only test because `main` deleted it (0.3 fixed
  the bug upstream, and 0.3 needs 1.85).
- Two `Display` pins were gated on `std` by a merge artifact and silently skipped in
  every feature row without it; `SecureEncoding` / `SecureDecoding` had lost their
  existence pin the same way.

### Testing / CI

- Core: 405 -> 422 tests. `secure-gate-compat`: **10 -> 258**. The compat suite had no
  `tests/integration.rs` aggregator, so cargo compiled none of `compat_suite/`,
  `compat_dual/` or `proptest_suite/` - 248 tests were dead code, and turning them on
  surfaced a file that had not compiled since the encoders became trait impls.
- New CI rows: a no-alloc `encoding-bech32` build, and the 1.70 rustdoc job above.

`secure-gate-compat`: test-suite activation and doc corrections; no code changes.

## [0.8.0-rc.11] - 2026-09-07

### Added

- **Backport of `main`'s 0.9.0-rc.8 newtype macros — `fixed_newtype!` /
  `dynamic_newtype!`** in `secure-gate-core` (#155). `struct` wrappers over
  `Fixed`/`Dynamic` so same-shaped secret roles are distinct types; no `From<Wrapper>`
  and no `Deref`; base-wrapper access opt-in per newtype and per direction.

- **Base32 encoding in `secure-gate-core`** (#158). Backported from `main`'s 0.9.0-rc.8.
  `ToBase32` / `FromBase32Str` behind `encoding-base32`, with wrapper and newtype
  forwarding and a `Base32Error` — RFC 4648 §6, uppercase and unpadded (the
  `otpauth://` TOTP/HOTP form). Lowercase and `=` padding are rejected. Uses `base32ct`
  **0.2** rather than `main`'s 0.3, which is edition 2024 / MSRV 1.85 and cannot build
  on this line; the 0.2 API is identical. See the core changelog.

### Changed

- **BREAKING (pre-release), `secure-gate-core` (#156, backport):** `len`/`byte_len`/
  `is_empty` moved from `RevealSecret` to `SecretLen`; `RevealSecret`/`RevealSecretMut`
  now cover every inner type; wrapper encoders are `ToHex`/`ToBase64Url`/`ToBech32`/
  `ToBech32m` trait impls. Migration is import lines only.

### Fixed

- **`secure-gate-core`:** `dynamic_no_deref` compile-fail snapshot is feature-invariant
  (#157); the DSE zeroization guard follows both spellings of LLVM's identical-code-folding
  alias (`.set a, b` on 1.85, `a = b` on current stable); stable and MSRV test jobs skip
  compile-fail cases by the `_compile_fail` name suffix.
- **`cargo audit` is clean** (#161): `crossbeam-epoch` 0.9.18 → 0.9.21 (RUSTSEC-2026-0204),
  `rand` 0.9.2 → 0.9.5 and 0.8.5 → 0.8.8 (RUSTSEC-2026-0097); the `bincode`
  dev-dependency is removed (RUSTSEC-2025-0141 — no patched version exists, so removal is
  the only fix). Two informational `atty` warnings remain, blocked by MSRV 1.70; see the
  core changelog.

### Testing / CI

- Core `--all-features` added to the stable test and lint matrices: `full` excludes `std`,
  so tests gated on `std` plus another feature previously compiled only in the MSRV job.

- **0.8-only workflow files renamed so their runs are identifiable** (`ci.yml` ->
  `ci-0.8.yml`, `fuzz-miri.yml` -> `fuzz-miri-0.8.yml`, `fuzz-quick.yml` ->
  `fuzz-quick-0.8.yml`). GitHub derives a workflow's display name from the *default
  branch's* copy of that file path, so this branch's `ci.yml` — correctly named
  `CI release/0.8` in the file — surfaced in the Actions list as `CI main/0.9`, main's
  name for the same path. Distinct paths give these three their own workflow entities
  and their real names. `audit.yml` (genuinely shared, branch-neutral name) and
  `dse-check.yml` are unchanged. CI badges in both READMEs and the path filters inside
  the renamed workflow were updated to match.

### Documentation

- **`secure-gate-core`:** the crate page lists `fixed_newtype!` / `dynamic_newtype!`
  alongside the alias macros; the `RevealSecret`/`SecretLen` re-export is split so
  rustdoc 1.70 (this line's MSRV toolchain) no longer ICEs on `cargo doc` — docs.rs
  (nightly) was never affected.

`secure-gate-compat`: version bump only; one test import (`SecretLen`); no code changes.

See the per-crate changelogs for full detail:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

- **RustCrypto integration example on `Fixed` (#144).** Backported from `main`.
  `secure-gate-core`'s `Fixed` rustdoc and README now document scoped in-place
  block-cipher ops via `GenericArray::from_mut_slice` inside `with_secret_mut`,
  contrasted with the copy-out shape that leaves plaintext in an unzeroized stack
  value. Compiled doctests; no API change. Also corrected docs left stale by the #156
  backport: the `RevealSecretMut` `len()`/`is_empty()` claim, the `dynamic_string_no_hex`
  sentence that contradicted this release's own preamble, and the status header on
  `docs/composability_restructure.md`.

## [0.8.0-rc.10] - 2026-07-06

### Security

- **Backport of the pre-v0.9.0 security sweep of `secure-gate-core`** (main
  PR #139) — three security fixes and two breaking API stabilizations; see
  [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md) for details:
  - `no_std` support is now real (`#![cfg_attr(not(feature = "std"), no_std)]`,
    dependency `std`-feature fixes) and verified in CI by cross-building for
    `thumbv7em-none-eabihf`.
  - `Fixed<[u8; N]>` deserialization rejects over-length sequences before its
    `Zeroizing` buffer can reallocate (realloc would free the first `N` secret
    bytes unzeroized).
  - Bech32/Bech32m HRP-checked decoding validates the HRP before materializing
    any payload bytes (mismatches previously dropped decoded secrets unzeroized).
  - Error enums are now build-invariant, heap-free, `Copy`, and
    `#[non_exhaustive]` (breaking; previously variant shapes differed between
    debug and release builds). 0.8-specific: `thiserror` is dropped —
    `std::error::Error` impls are hand-written and gated behind the `std`
    feature (MSRV 1.70 predates `core::error::Error`).
  - `RevealSecret::into_inner` works for `Fixed<[u8; N]>` with `N > 32` via the
    new `SentinelValue` trait (breaking bound change from `Default`).

### Fixed

- **`secure-gate-compat` is now genuinely `no_std`** — see
  [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md).

See the per-crate changelogs for full detail:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

## [0.8.0-rc.9] - 2026-05-10

### Added

- **`rust-toolchain.toml`** (workspace root) — pins the workspace to Rust
  channel `1.70` (matching the LTS MSRV) with `cargo`, `rustc`, `rust-std`,
  `clippy`, and `rustfmt` components. Contributors no longer need
  `cargo +1.70 …` for local builds; switching from `main` to this branch
  swaps in the 1.70 toolchain automatically. CI jobs that set an explicit
  toolchain still override the file.
- **`.cargo/config.toml`** (workspace root) — sets
  `[resolver] incompatible-rust-versions = "fallback"`. Cargo 1.70 itself
  ignores this field (no MSRV-aware resolver until 1.84+), so it's a no-op
  on the LTS toolchain. It takes effect the moment anyone runs
  `cargo +1.85 update` against this branch — useful for bulk lockfile
  refreshes that need to keep crate versions compatible with
  `rust-version = "1.70"`. Day-to-day, the LTS branch's `Cargo.lock`
  remains frozen and updates use targeted `--precise` pins.

### Security

- **Second-LLM audit follow-ups in `secure-gate-core`** — closure-panic
  zeroization for `Dynamic::new_with`, documented realloc and serde
  zeroization boundaries, and expanded DSE CI matrix (Findings 1–4).
- **`secure-gate-compat` Finding 5** — partial mitigation for
  `SecretBox::init_with` / `try_init_with` clone-panic leaks.

### Changed

- **`RevealSecret::len()` now returns element count** (breaking for
  non-`u8` element types); use `byte_len()` for byte size. Unchanged for
  `Dynamic<Vec<u8>>`, `Dynamic<String>`, and `Fixed<[u8; N]>`.

See the per-crate changelogs for full detail:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

## [0.8.0-rc.8] - 2026-04-03

### Added

- **Streaming I/O for `Dynamic<Vec<u8>>`** — `std::io::Write` impl and
  `DynamicReader` + `as_reader()` for `std::io::Read` (gated behind the
  existing `std` feature). See
  [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md).

## [0.8.0-rc.7] - 2026-03-30

### Documentation

- **Workspace README.md added** — new top-level `README.md` introduces the workspace, lists both crates (`secure-gate` and `secure-gate-compat`), provides a quick-start guide, and links to per-crate documentation.
- **Security audit warning** — README files for the workspace, `secure-gate-core`, and `secure-gate-compat` now include a prominent warning that the library has not yet undergone an independent security audit.
- **`secure-gate-compat` README cleanup** — removed outdated badges; updated migration notes to reflect current workspace structure.

### Changed
- Split the project into a Cargo workspace with `secure-gate-core` (minimal, auditable core library published as `secure-gate`) and `secure-gate-compat` (isolates all `secrecy` migration shims, tests, and related code).
  - **This significantly reduces the security blast radius**: vulnerabilities or supply-chain issues in the compat layer can no longer impact the main library.
  - It also streamlines maintenance, CI test matrices, dependency management, and independent evolution of each crate.
  - Root `Cargo.toml` now defines the workspace (`members`, `resolver = "2"`, shared `[workspace.package]` metadata for version/edition/MSRV/license/etc.) and excludes `secure-gate-core/fuzz`; sub-crates inherit via `.workspace = true` fields.
