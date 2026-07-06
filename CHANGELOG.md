# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
