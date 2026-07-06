# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0-rc.7] - 2026-07-06

### Fixed

- **The crate is now genuinely `no_std`.** It advertised the `no-std` category
  but never declared `#![no_std]`, so it silently linked `std` and failed to
  build on bare-metal targets. The crate root is now unconditionally
  `#![no_std]` (the shims need `alloc`, never `std`); the one prelude-only
  `ToString` usage in `compat::v08` now imports from `alloc`. Verified in CI by
  cross-building for `thumbv7em-none-eabihf` (with and without
  `secrecy-compat`).

## [0.9.0-rc.6] - 2026-05-10

### Security

- **Finding 5 — `SecretBox::init_with` / `try_init_with` clone-panic leak
  (MEDIUM, partial mitigation).** The closure return value is now wrapped in
  `Zeroizing<S>` before `S::clone()` is called, so a panic during clone (e.g.,
  OOM in `Vec::clone`) zeroes the original on unwind. The previous code
  dropped the original as plain `S`, which only zeroizes when `S: ZeroizeOnDrop`
  — the `S: Zeroize + Clone` bound alone is not enough.

  **Residual best-effort window remains:** the cloned copy is briefly held as
  an unwrapped stack temporary while it is moved into `Box::new`. If
  `Box::new` itself panics (e.g., OOM under a panicking allocator) the
  temporary drops as `S`, which still only zeroizes when `S: ZeroizeOnDrop`.
  Closing this window would require tightening the trait bound to
  `ZeroizeOnDrop`, which is rejected as an API break vs. `secrecy::SecretBox`
  whose contract this shim mirrors. The residual window is now precisely
  documented in the rustdoc; users who need full panic-safety should prefer
  `init_with_mut`, which has no stack-temporary surface.

  New regression tests (`init_with_zeros_original_on_clone_panic` /
  `try_init_with_zeros_original_on_clone_panic`) in
  `tests/compat_suite/edge_cases.rs` use a custom `S` whose `Clone` always
  panics and verify the original's `Zeroize::zeroize` runs during unwind.

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
