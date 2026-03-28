# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

(v0.8.0-rc.7-dev)

### Changed
- Root `Cargo.toml` is now a workspace manifest with `members = ["secure-gate-core", "secure-gate-compat"]` and `resolver = "2"`.
- Added `[workspace.package]` for shared metadata (version, edition = "2021", rust-version = "1.70", license, repository, etc.).
- All sub-crate `Cargo.toml` files now inherit `version.workspace = true`, `edition.workspace = true`, etc.
