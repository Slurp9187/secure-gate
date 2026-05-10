# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
