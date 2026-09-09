# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Caller-chosen bech32 / bech32m code length** in `secure-gate-core` (#171).
  `Bech32Sized<N>` / `Bech32mSized<N>` let the caller pick the code length instead of
  taking the BCH bound; the default is now 1023, not 8191.


### Changed

- **BREAKING, `secure-gate-core`:** every encoder returns `EncodedSecret`, and
  `RevealSecret::into_inner()` returns the plain value rather than a wrapper. The
  encoding traits no longer accept string-shaped inputs — encode takes byte-shaped
  types only.

- **BREAKING, `secure-gate-compat`:** `serde-serialize` and `serde-deserialize` now
  pull in `dep:serde`. Neither feature compiled on its own before.


### Removed

- **BREAKING, `secure-gate-core`:** `InnerSecret<T>`, the `*_zeroizing` encoder
  variants, `AsRef<str>` / `AsRef<[u8]>` on `EncodedSecret`, the `SecureEncoding` /
  `SecureDecoding` marker traits, `DecodingError`, `Bech32Error::ConversionFailed`, and
  the `encoding-bech32m` feature — folded into `encoding-bech32`, not aliased.


### Security

- **Bech32 encoding left unwiped partial copies of the secret on the heap** in
  `secure-gate-core`. The encoder chain is now driven directly, with no stack staging of
  the encoded secret and the buffer allocated exactly once.


### Dependencies

- **`thiserror` removed** from `secure-gate-core`; `zeroize_derive` moved to
  `[dev-dependencies]`. `secure-gate-compat` entered this cycle already without
  `thiserror`, so nothing was removed there.


### Testing

- **CI gained a rustdoc job (#175).** No workflow ran rustdoc at all, so a broken
  intra-doc link in the shipping docs would have reached docs.rs unnoticed. It builds
  `--no-deps --all-features` under `-D warnings` on stable. What it enforces is the
  *feature set* docs.rs builds — `all-features = true` — not docs.rs's toolchain or
  its `--cfg docsrs`; those are a separate nightly step. Minimal builds stay
  best-effort, and `README.md` records the policy.

- **docs.rs feature badges, and a nightly step that guards them.** `--cfg docsrs` was
  configured but unread until `#![cfg_attr(docsrs, feature(doc_cfg))]` gave it an
  effect; the `docs` job now runs that exact configuration on nightly so a rename of
  the gate cannot break docs.rs silently. See the core changelog.

## [0.9.0-rc.8] - 2026-09-07

### Added

- **Nominal newtypes — `fixed_newtype!` / `dynamic_newtype!`** in `secure-gate-core`
  (#155). `struct` wrappers over `Fixed`/`Dynamic` so same-shaped secret roles (an
  encryption key and a MAC key, an API key and a webhook secret) are distinct types
  and a swapped argument is a compile error. No `From<Wrapper>` and no `Deref`;
  base-wrapper access is opt-in per newtype and per direction (`FromWrapper` /
  `IntoWrapper` / `WrapperAccess`). Design record: `secure-gate-core/docs/nominal_newtypes.md`.

- **Base32 encoding in `secure-gate-core`** (#158). `ToBase32` / `FromBase32Str`
  behind `encoding-base32`, with wrapper and newtype forwarding and a `Base32Error`
  — RFC 4648 §6, uppercase and unpadded (the `otpauth://` TOTP/HOTP form) via the
  constant-time `base32ct` crate. Lowercase and `=` padding are rejected. See the
  core changelog.

### Changed

- **BREAKING (pre-release), `secure-gate-core` (#156):** `len`/`byte_len`/`is_empty`
  moved from `RevealSecret` to a new `SecretLen` trait, and `RevealSecret` /
  `RevealSecretMut` now cover every inner type (custom inner newtypes are finally
  readable). Wrapper encoding methods (`to_hex`, `to_base64url`, `try_to_bech32*`,
  `_zeroizing` variants) are now impls of the `ToHex` / `ToBase64Url` / `ToBech32` /
  `ToBech32m` traits. Migration from earlier RCs is import lines only; call syntax is
  unchanged. Design record: `secure-gate-core/docs/composability_restructure.md`.

### Removed

- **BREAKING, `secure-gate-core` (#149):** `Display` on `EncodedSecret`. Write
  `&*encoded` where `Display` was relied on.

### Security

- **`secure-gate-core`:** `std::io::Write` on `Dynamic<Vec<u8>>` no longer leaves a
  copy of the secret in the outgoing buffer when it grows (#152); `InnerSecret<T>`
  now implements `Clone`, so `inner.clone()` can no longer fall through `Deref` to an
  unprotected `T` (#146).

### Fixed

- **`cargo audit` is clean again** — it had been red on `main`'s scheduled runs since
  2026-08-10. `Cargo.lock`: `crossbeam-epoch` 0.9.18 → 0.9.21 (RUSTSEC-2026-0204, the
  one vulnerability; dev-only via `criterion`), `anyhow` 1.0.102 → 1.0.104
  (RUSTSEC-2026-0190), `chacha20` 0.10.0 → 0.10.2 (yanked). The `bincode`
  dev-dependency is removed (RUSTSEC-2025-0141, unmaintained — the advisory has no
  patched version and covers 2.x too, so removal is the only fix) along with its
  single test; see the core changelog.
- **`secure-gate-core`:** the DSE zeroization guard emits assembly to an explicit
  path and can no longer pass on stale output or silently skip on nightly (#150), and
  follows both spellings of LLVM's identical-code-folding alias (`.set a, b` on 1.85,
  `a = b` on rustc 1.98); the `dynamic_no_deref` compile-fail snapshot is now
  feature-invariant (#157).

### Testing / CI

- Compile-fail enforcement that `Fixed`/`Dynamic` have no `Deref`/`AsRef`, and a
  `compile-fail` job pinned to Rust 1.85 that actually runs the trybuild suite (#148).
  Stable test jobs skip compile-fail cases by the `_compile_fail` name suffix, so new
  cases cannot leak onto a drifting toolchain.
- Core `--all-features` added to the test and lint matrices: `full` excludes `std`, so
  tests gated on `std` plus another feature previously compiled in no CI entry.

`secure-gate-compat`: version bump only; three test files gain the `SecretLen` import
the #156 split requires. No code changes.

### Documentation

- **RustCrypto integration example on `Fixed` (#144).** `secure-gate-core`'s `Fixed`
  rustdoc and README now document scoped in-place block-cipher ops via
  `GenericArray::from_mut_slice` inside `with_secret_mut`, contrasted with the
  copy-out shape that leaves plaintext in an unzeroized stack value. Compiled
  doctests; no API change. Also corrected two docs left stale by the #156 restructure:
  the `RevealSecretMut` `len()`/`is_empty()` claim, and the status header on
  `docs/composability_restructure.md`.

- **`secure-gate-core`:** the crate page lists `fixed_newtype!` / `dynamic_newtype!`
  alongside the alias macros, and `SecretLen` gets its own crate-level re-export doc
  (the `RevealSecret`/`SecretLen` re-export is split so the 0.8 line's rustdoc 1.70,
  which ICEs on grouped re-exports, can keep sharing this file).

See the per-crate changelogs for full detail:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

## [0.9.0-rc.7] - 2026-07-06

### Security

- **Pre-v0.9.0 security sweep of `secure-gate-core`** — three security fixes and
  two breaking API stabilizations; see
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
    debug and release builds).
  - `RevealSecret::into_inner` works for `Fixed<[u8; N]>` with `N > 32` via the
    new `SentinelValue` trait (breaking bound change from `Default`).

### Fixed

- **`secure-gate-compat` is now genuinely `no_std`** — see
  [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md).

See the per-crate changelogs for full detail:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

## [0.9.0-rc.6] - 2026-05-10

### Added

- **`rust-toolchain.toml`** (workspace root) — pins the workspace to Rust
  channel `1.85` (matching the declared MSRV) with `cargo`, `rustc`,
  `rust-std`, `clippy`, and `rustfmt` components. Contributors no longer
  need `cargo +1.85 …` for local builds; switching to `release/0.8` swaps
  in that branch's own `1.70` toolchain file automatically. CI jobs that
  set an explicit toolchain still override the file.
- **`.cargo/config.toml`** (workspace root) — enables the MSRV-aware
  resolver via `[resolver] incompatible-rust-versions = "fallback"`. On
  the 0.9 line (cargo 1.85+) `cargo update` now refuses to select crate
  versions whose `rust-version` exceeds the workspace's `1.85`,
  preventing accidental MSRV breakage from routine dependency refreshes.

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

## [0.9.0-rc.5] - 2026-04-03

### Added

- **Streaming I/O for `Dynamic<Vec<u8>>`** — `std::io::Write` impl and `DynamicReader` + `as_reader()` for `std::io::Read` (gated behind the existing `std` feature). Makes secure streaming the ergonomic default.

### Documentation

- **Workspace README.md added** — new top-level `README.md` introduces the workspace, lists both crates (`secure-gate` and `secure-gate-compat`), provides a quick-start guide, and links to per-crate documentation.
- **Security audit warning** — README files for the workspace, `secure-gate-core`, and `secure-gate-compat` now include a prominent warning that the library has not yet undergone an independent security audit.
- **`secure-gate-compat` README cleanup** — removed outdated badges; updated migration notes to reflect current workspace structure.

## [0.9.0-rc.4] - 2026-03-30

### Changed

- Major workspace refactor for v0.9:
  - `secure-gate-core` is the minimal, auditable foundation (published as `secure-gate`).
  - `secure-gate-compat` isolates all `secrecy` migration shims, tests, and related code.
  - **Significantly reduces the security blast radius**: vulnerabilities in the compat layer can no longer impact the main library.
  - Streamlines maintenance, CI matrices, dependency management, and independent evolution of each crate.
- Updated all documentation, links, and badges to the `main` branch.
- MSRV raised to 1.85 for the 0.9 line (see per-crate changelogs for details).
- Comprehensive security documentation updates (3-tier access model restored in core `SECURITY.md`, dedicated compat `SECURITY.md` added).

See the per-crate changelogs for detailed, version-specific changes:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md) — core library changes
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md) — compatibility layer changes
