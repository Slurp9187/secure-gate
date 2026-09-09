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

- **`publish = false` was not followed through to anything a user reads.** The root
  README still listed this crate under "Published as" with a crates.io link, both READMEs
  and `MIGRATING_FROM_SECRECY.md` gave a `version = "0.9"` dependency line that cannot
  resolve, and `Cargo.toml` advertised a `documentation` URL on docs.rs that will never
  build. Install snippets are now git dependencies and the docs.rs URL is gone.

- **The migration steps named the wrong crate — the same class as the
  `secure_gate::compat::` paths fixed above.** Step 1 in both `v08` and `v10` told
  readers to add `secure-gate` with `features = ["secrecy-compat"]`; that feature is on
  *this* crate. Step 5 said to remove the feature when it should say the dependency.

- **`secrecy-compat` was documented as enabling the shim modules.** It does not — `v08`
  and `v10` carry no `cfg` on it and always compile. The module docs and the compat
  README now match the corrected `Cargo.toml` comment.

- **Three intra-doc links pointed at the wrong item, resolving silently.**
  `mod.rs`'s `CloneableSecret` was labelled `secure_gate::CloneableSecret` but targeted
  `crate::CloneableSecret`, which is compat's own marker — clicking it never left the
  compat trait. `v10`'s migration table, headed "secure-gate native", linked that same
  compat trait. `mod.rs`'s `SerializableSecret` doc said it re-exports
  `crate::SerializableSecret` when the `pub use` is `secure_gate::SerializableSecret`.

- **`ExposeSecret`'s docs credited `RevealSecret` with byte-length metadata.**
  `len` / `byte_len` / `is_empty` live on `SecretLen`, a separate trait.

- **`fuzz/` used `.to_string()` where the crate documents `into_inner()`.**
  `EncodedSecret` has no `Display`; that call went through `Deref` to `str::to_string()`
  — the copy `encoded_secret.rs` explicitly tells auditors to sweep for. Core's fuzz
  harness already used the named exit; this one now does too.

- **`proptest_suite` was gated on this crate's `alloc`, which `secrecy-compat` does not
  enable.** `secrecy-compat` turns on `secure-gate/alloc`, a different feature, so
  `--features secrecy-compat --all-targets` skipped the file entirely and only
  `--all-features` ever compiled it. That is why the MSRV break could hide. The
  redundant conjunct is dropped; the parent module already gates on `secrecy-compat`.

- **`SECURITY.md` and `MIGRATING_FROM_SECRECY.md` gave a `cargo test` line that fails.**
  This is a virtual workspace, so `cargo test --features secrecy-compat` needs
  `-p secure-gate-compat`. `SECURITY.md`'s "last updated" stamp also still read March
  2026 despite this cycle rewriting its Tier 3 guidance.

- **`v08` was described as having "no const-generic arrays".** It has them —
  `impl<T: fmt::Debug, const N: usize> DebugSecret for [T; N]`.

- **Eleven intra-doc link errors — the whole crate's rustdoc output was failing.**
  `cargo doc --all-features` exited 101 under `-D warnings`. Six were unresolved links
  in `v08`'s API table: rustdoc merges the outer `///` on `pub mod v08;` with the inner
  `//!` and resolves the result in `crate::compat` scope, where `Secret`,
  `SecretString`, `SecretVec`, `SecretBox` and `DebugSecret` are not in scope — they
  live one module down. They now carry explicit `crate::compat::v08::` targets, which
  resolve from either scope. The other five were redundant explicit targets whose label
  already resolved to the same item. Verified in the rendered HTML that all eleven reach
  the intended items, rather than merely resolving.

- **Five more redundant explicit link targets that only nightly reports.** Stable
  resolves the merged module docs in each submodule's own scope, where the bare labels do
  not resolve, so it stays quiet; nightly resolves them in `crate::compat` scope, where
  they do — making the explicit targets redundant. The human renderer prints these with no
  source span at all, which is why they were initially left alone; `--message-format=json`
  carries the spans the terminal output drops. Confirmed the five now resolve to the same
  items the explicit targets named, and that dropping them is clean on 1.85, stable, 1.98
  and nightly — the concern that stable might then fail to resolve them did not hold.

- **Six `secure_gate::compat::` paths in `MIGRATING_FROM_SECRECY.md` that do not
  resolve.** Core exposes no `compat` module and the crate is `secure_gate_compat`. The
  file is not `include_str!`'d, so no rustdoc pass and no doctest ever read it, and it
  is listed in `include` — it would ship in a tarball if this crate were ever
  published, which as of this release it explicitly is not. The adjacent `use
  secure_gate::Dynamic;` / `Fixed` lines are correct and unchanged.

- **`tests/proptest_suite/` did not compile on the declared MSRV under
  `--all-features`.** `prop_assert_eq!(*v08_back.expose_secret(), arr)` dereferenced a
  `[u8; 32]`, which rustc rejects with E0614 on 1.85 through 1.97; 1.98 accepts it. The
  module is gated on this crate's own `alloc` feature, which only `--all-features` turns
  on, and nothing caught the gap: CI's `stable` had moved to 1.98, and the MSRV job
  compiles the library alone. The assertion now compares references, matching the two
  round-trip tests beside it.

- **`fuzz/` did not compile after the encoder rewrite.** `try_to_bech32` returns
  `EncodedSecret` rather than `String` now, so `FuzzBech32String(encoded)` was a type
  error and every compat fuzz target failed to build. The value is a synthetic bech32
  string generated from fuzzer bytes, not a secret, so it converts through
  `EncodedSecret`'s `Deref<Target = str>`. The workflow's path filters also now include
  `secure-gate-core/src/**`: this crate builds against `secure-gate`, so a core API
  change can break it with nothing under `secure-gate-compat/` touched — which is
  exactly how this survived, visible only to the nightly cron.

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
