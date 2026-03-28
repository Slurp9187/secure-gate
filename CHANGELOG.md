# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(v0.9.0-rc-4-dev)

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
