# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0-rc.9] - 2026-05-09

### Release Notes

- **v0.8.0-rc.9 release candidate** — Pre-release of the 0.8 LTS series (Rust edition 2021, MSRV 1.70). Not yet recommended for production use.
- Parallel to the v0.9.0-rc.6 line on `main` (Rust edition 2024, MSRV 1.85). Functionality, security model, and test coverage are at parity; the two lines diverge only on toolchain floor and a small set of dependency surfaces (`rand` 0.9 vs 0.10, `subtle` 2.5 vs 2.6, `zeroize` 1.7 vs 1.8, `base16ct` 0.2 vs 1, `base64ct` =1.6 vs 1).
- Major security and architectural improvements (real `Drop` + zeroize, 3-tier access model, opt-in marker-trait gating, panic-safe `from_protected_bytes`, allocator-level zeroize verification via `ProxyAllocator`, LLVM-level DSE asm regression guard) are in place.
- Open before stable: same documentation gaps as the 0.9 line (`Dynamic::new` OOM-panic boundary, `#[unsafe(no_mangle)]` in published binary).
- Recommended for users on Rust 1.70–1.84 who cannot move to edition 2024; users on Rust 1.85+ should prefer `secure-gate = "0.9"`.

See the per-crate changelogs for detailed changes:

- [`secure-gate-core/CHANGELOG.md`](secure-gate-core/CHANGELOG.md)
- [`secure-gate-compat/CHANGELOG.md`](secure-gate-compat/CHANGELOG.md)

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
