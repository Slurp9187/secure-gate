# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-05-08

### Release Notes

- **Stable v0.9.0 release** — First stable version of the compat shim on the 0.9 line (Rust edition 2024, MSRV 1.85). Tracks `secure-gate = "0.9"`.
- No API changes since `0.9.0-rc.5`; all `secrecy` v0.8 / v0.10 migration shims (`Secret`, `SecretBox`, `SecretString`, `SecretSlice`, `SecretVec`, `DebugSecret`) plus dual-version parity tests, fuzz targets, and migration guide are considered stable.
- Sister to v0.8.0 on `release/0.8` (Rust 2021 / MSRV 1.70).
- Recommended for teams migrating off `secrecy` who target Rust 1.85+. Prefer dropping the `secrecy-compat` feature once migration is complete.

## [0.9.0-rc.5] - 2026-04-03

### Documentation

- **README security audit warning** — `secure-gate-compat/README.md` now includes a prominent warning that the library has not yet undergone an independent security audit.
- **README cleanup** — removed outdated badges; migration notes updated to reflect current workspace structure.

## [0.9.0-rc.4] - 2026-03-30

### Changed

- Extracted the compatibility layer into its own published crate (`secure-gate-compat`).
  - Previously part of the main `secure-gate` crate; now isolated to reduce the security blast radius and simplify the core library.
  - Includes all `secrecy-compat` features, `v08`/`v10` shims, migration tests, dual-compat parity tests, and related documentation.
- Updated imports, manifests, doctests, and CI to reflect the new workspace structure (`secure-gate-core` + `secure-gate-compat`).

See the core [`secure-gate` changelog](../secure-gate-core/CHANGELOG.md) for the full project history (including the initial workspace split and all pre-0.9 changes).
