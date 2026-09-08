# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0-rc.9] - 2026-09-08

### Changed

- **`publish = false`.** This crate is experimental and has never been intended for
  crates.io, but nothing enforced that: with no `publish` key, a workspace-wide publish
  would have pushed it alongside `secure-gate`. The intent is now mechanical —
  `cargo publish -p secure-gate-compat` is refused, and `cargo publish -p secure-gate`
  is unaffected.

- **`serde-serialize` and `serde-deserialize` now pull in `dep:serde`.** Neither
  compiled on its own: the `#[cfg(feature = ...)]` blocks in `src/compat/` name `serde`
  types directly, and `secure-gate/serde-serialize` names the *dependency's* feature,
  not this crate's same-named one. Only `secrecy-compat` happened to drag `serde` in,
  which is why the gap went unnoticed.

- **`zeroize` is now an explicit dev-dependency carrying `zeroize_derive`.** The test
  suite's `#[derive(Zeroize)]` previously arrived by feature unification from
  `secure-gate`, which no longer enables `zeroize_derive`. The shim itself does not need
  the derive, and neither does real `secrecy` — 0.8 and 0.10 both depend on `zeroize`
  with `default-features = false`.

- **The `secrecy-compat` feature comment describes what the feature actually does.** It
  claimed to "enable" the `v08` / `v10` shim modules, which carry no `cfg` on it and
  always compile. What it really does is turn on the core features the shims need
  (`alloc`, `cloneable`, `serde-serialize`) plus this crate's `serde` dependency, and
  gate the whole compat test surface. It also names the crate path correctly.

- **`SECURITY.md`'s Tier 3 mitigation matches the wrapper's actual behaviour.** It told
  auditors that zeroization transfers to a returned `InnerSecret<T>`; that type is gone
  in this release, and `into_inner` now returns the plain value, so protection ends at
  the call and the caller owns the secret's lifetime from there.

### Fixed

- **Eleven intra-doc link errors — the whole crate's rustdoc output was failing.**
  `cargo doc --all-features` exited 101 under `-D warnings`. Six were unresolved links
  in `v08`'s API table: rustdoc merges the outer `///` on `pub mod v08;` with the inner
  `//!` and resolves the result in `crate::compat` scope, where `Secret`,
  `SecretString`, `SecretVec`, `SecretBox` and `DebugSecret` are not in scope — they
  live one module down. They now carry explicit `crate::compat::v08::` targets, which
  resolve from either scope. The other five were redundant explicit targets whose label
  already resolved to the same item. Verified in the rendered HTML that all eleven reach
  the intended items, rather than merely resolving.

- **Six `secure_gate::compat::` paths in `MIGRATING_FROM_SECRECY.md` that do not
  resolve.** Core exposes no `compat` module and the crate is `secure_gate_compat`. The
  file is not `include_str!`'d, so no rustdoc pass and no doctest ever read it, but it
  does ship in the published tarball via `include`. The adjacent `use
  secure_gate::Dynamic;` / `Fixed` lines are correct and unchanged.

- **`tests/proptest_suite/` did not compile on the declared MSRV under
  `--all-features`.** `prop_assert_eq!(*v08_back.expose_secret(), arr)` dereferenced a
  `[u8; 32]`, which rustc rejects with E0614 on 1.85 through 1.97; 1.98 accepts it. The
  module is gated on this crate's own `alloc` feature, which only `--all-features` turns
  on, and nothing caught the gap: CI's `stable` had moved to 1.98, and the MSRV job
  compiles the library alone. The assertion now compares references, matching the two
  round-trip tests beside it.

### Removed

- **`scripts/package_it.py`.** Obsolete packaging script.

## [0.9.0-rc.8] - 2026-09-06

### Changed

- Version bump only, tracking the workspace release; depends on `secure-gate`
  0.9.0-rc.8. No code changes in this crate.

### Testing

- Three test files (`tests/migration_full.rs`, `tests/compat_suite/edge_cases.rs`,
  `tests/compat_suite/examples.rs`) import `secure_gate::SecretLen` for their
  `len()` / `is_empty()` calls on `Fixed`/`Dynamic`, following the `SecretLen` split
  in `secure-gate` (#156). This is the same one-line migration the core changelog
  describes for downstream code.

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
