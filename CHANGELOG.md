# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-11-17

### Changed
- Renamed `SecurePasswordMut` → `SecurePasswordBuilder` for clarity and builder-pattern familiarity
  - `SecurePasswordMut` is now a **deprecated alias** with a compiler warning
  - No breaking change — existing code continues to compile
- Added `into_password()` and `build()` methods on `SecurePasswordBuilder` for ergonomic conversion to the immutable `SecurePassword`
- All public aliases (`SecurePassword`, `SecurePasswordBuilder`, `SecureBytes`, `SecureStr`, etc.) are now available even when the `zeroize` feature is disabled
  - Fixes compilation and testing with `--no-default-features`

### Fixed
- Resolved trait conflicts in `no-default-features` mode
- Improved test assertions to use `.expose()` directly (more idiomatic)

## [0.3.0] - 2025-11-13
- Initial public release
- Zero-overhead secure wrappers with optional `zeroize` and `stack` features
- `Secure<T>`, `SecureBytes`, `SecureStr`, fixed-size key types, and password aliases
