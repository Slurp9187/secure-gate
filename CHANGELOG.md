# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

CHANGELOG.md#12-25
## [Unreleased]

=======
### Added

- **Streaming I/O for `Dynamic<Vec<u8>>`** — `std::io::Write` impl and `DynamicReader` + `as_reader()` for `std::io::Read` (gated behind the existing `std` feature). Makes secure streaming the ergonomic default.

### Documentation

- **Workspace README.md added** — new top-level `README.md` introduces the workspace, lists both crates (`secure-gate` and `secure-gate-compat`), provides a quick-start guide, and links to per-crate documentation.
- **Security audit warning** — README files for the workspace, `secure-gate-core`, and `secure-gate-compat` now include a prominent warning that the library has not yet undergone an independent security audit.
- **`secure-gate-compat` README cleanup** — removed outdated badges; updated migration notes to reflect current workspace structure.

## [0.8.0-rc.7] - 2026-03-30

### Changed
- Split the project into a Cargo workspace with `secure-gate-core` (minimal, auditable core library published as `secure-gate`) and `secure-gate-compat` (isolates all `secrecy` migration shims, tests, and related code).
  - **This significantly reduces the security blast radius**: vulnerabilities or supply-chain issues in the compat layer can no longer impact the main library.
  - It also streamlines maintenance, CI test matrices, dependency management, and independent evolution of each crate.
  - Root `Cargo.toml` now defines the workspace (`members`, `resolver = "2"`, shared `[workspace.package]` metadata for version/edition/MSRV/license/etc.) and excludes `secure-gate-core/fuzz`; sub-crates inherit via `.workspace = true` fields.
