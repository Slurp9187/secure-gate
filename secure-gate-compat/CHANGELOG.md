# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(v0.8.0-rc.7-dev)

### Changed
- Extracted the compatibility layer into its own published crate (`secure-gate-compat`).
  - Previously part of the main `secure-gate` crate; now isolated to reduce the security blast radius and simplify the core library.
  - Includes all `secrecy-compat` features, `v08`/`v10` shims, migration tests, dual-compat parity tests, and related documentation.
- Updated imports, manifests, doctests, and CI to reflect the new workspace structure (`secure-gate-core` + `secure-gate-compat`).
- Added basic `README.md` with correct badges and migration-focused installation instructions.

### Added
- Initial `MIGRATING_FROM_SECRECY.md` (moved from core).
- Compile-fail tests and `trybuild` setup for compat-specific invariants.
- Doctests for `DebugSecret`, `Secret`, `SecretBox`, and migration examples.
- Initial release as a standalone crate (extracted from `secure-gate`).

See the main [`secure-gate` changelog](https://github.com/Slurp9187/secure-gate/blob/release/0.8/secure-gate-core/CHANGELOG.md) for pre-split history (0.1.0–0.8.0-rc.6).
