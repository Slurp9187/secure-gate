# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0-rc.12] - 2026-09-09

### Changed

- **`SECURITY.md` gained the zero-length-secret entry from `main`.** A zero-length secret
  is accepted everywhere and fails silently: `Fixed<[u8; 0]>` constructs, reports
  `len() == 0`, still prints `[REDACTED]`, encodes to `""`, and compares `ct_eq`-equal to
  any other empty. `fixed_alias!(Name, 0)` is a compile error, but that guard lives in the
  macro alone — `type Name = Fixed<[u8; 0]>;` bypasses it. Verified on 1.70 against this
  branch rather than copied on faith from `main`.

- **`fuzz/Cargo.lock` is tracked.** Fuzzing is part of this crate's assurance story, and
  a crash is only useful if it still reproduces later. `arbitrary` decides how a stored
  corpus byte string maps to a generated value, so a minor bump there can change what a
  saved reproducer decodes to and a crash can quietly stop crashing. Pinning the lock
  keeps "this input failed on this tree" durable. The crate's own `Cargo.lock` is tracked
  for the same reason. `target/`, `corpus/`, `artifacts/` and `coverage/` stay ignored —
  those are generated, and the corpus is not a build input.

- **The repository is a single crate at the root.** With `secure-gate-compat` removed the
  workspace had one member, so `secure-gate-core/` is dissolved: `src/`, `tests/`,
  `benches/` and `fuzz/` move to the root, and the crate's `README.md`, `CHANGELOG.md`
  and `SECURITY.md` become the repository's. Design records move to `docs/design/`.
  `cargo publish` no longer needs `-p secure-gate`; the published crate is unchanged.

  Mirrors the same change on `main`, re-derived against this branch rather than copied —
  the workflow set differs (`ci-0.8.yml`, `fuzz-miri-0.8.yml`, `fuzz-quick-0.8.yml`), the
  MSRV stays 1.70 and the edition stays 2021, and this branch carries `test_all.sh`,
  which moves up with the rest.

  `ROADMAP.md` is deleted rather than moved, matching `main`, which dropped it earlier in
  this cycle. Its only content this branch still needed was the release-branch table, and
  the README's *Branch support* section already carries that; the rest described 0.9
  plans that do not apply to an LTS line and was stamped March 2026.

  The old root `README.md` and `CHANGELOG.md` were workspace summaries of a workspace
  that no longer exists; the crate's own supersede them and are what ships. Their content
  remains in git history.

> Everything below is unreleased. `0.8.0-rc.11` is the newest version of this line on
> crates.io; `0.8.0-rc.12` was tagged but never published, so its entries live here
> rather than under a heading claiming a release that did not happen. Only
> `secure-gate` has ever been published.

### Added

- **`Case` on the bech32 encoders — `try_to_bech32`, `try_to_bech32m` and both
  `_sized::<N>` forms now take `Case::Lower` or `Case::Upper`.** Requested by a
  downstream adopter tracking this branch, whose bech32-encoded private identity key is
  in age's uppercase `AGE-SECRET-KEY-…` form. Encoders emitted lowercase only, so the
  value that most warranted `EncodedSecret` shipped as a plain unzeroized `String`.

  Uppercasing happens inside the encoder, on the exact-capacity buffer it already owns:
  ASCII case conversion is length-preserving, so it cannot reallocate and the secret is
  never copied. BIP-173 defines the checksum over the lowercase form and accepts either
  pure case, so uppercasing HRP, separator, payload and checksum together stays valid
  and decodable.

  **The parameter's absence elsewhere is the safety property.** `to_base64url` and
  `to_base32` take no `Case`, because no legitimate choice exists: base64url gives
  `a`–`z` and `A`–`Z` distinct meanings, so converting case destroys the value
  (`3q2-7w` → `3Q2-7W` fails to decode), and RFC 4648 §6 base32 is uppercase by
  definition with a decoder that rejects anything else. A caller cannot ask for a
  conversion that would corrupt the value, because there is no parameter to pass.
  `to_hex` / `to_hex_upper` are unchanged: hex decodes mixed case either way, so there
  is no hazard there to close.

  This replaces a general `EncodedSecret::make_ascii_uppercase` / `make_ascii_lowercase`
  pair that existed briefly on this branch and was never released. Those were general
  over a type that deliberately erases which encoder produced it, so they could not
  check anything — and since `EncodedSecret::new` is `pub(crate)`, the only values that
  type can hold are the five encodings this crate emits, two of which corrupt under case
  change. The generality was confined entirely to the set where the operation is
  sometimes wrong.


### Changed

- **BREAKING: the four bech32 encoders take a `Case`.** `try_to_bech32(hrp)` becomes
  `try_to_bech32(hrp, Case::Lower)`, and likewise for `try_to_bech32m` and both
  `_sized::<N>` forms, on `Fixed`, `Dynamic` and the newtype macros. These call sites
  are already being edited in this unreleased candidate: rc.11 returned
  `Result<String, _>` and rc.12 returns `Result<EncodedSecret, _>`, with the
  `*_zeroizing` twins removed. The parameter enlarges an edit callers are already
  making rather than adding a migration of its own.
- **BREAKING — every encoder returns `EncodedSecret` (#172).** The `*_zeroizing` twins
  are gone, so the short name is the safe one. An encoded secret is a second full copy of
  the secret in a longer alphabet; it is wiped by default now, and the unprotected form
  costs a named call.
- **BREAKING — `into_inner` returns the plain value (#172).** Protection ends at that
  call rather than following the value into the caller.
- **BREAKING — `encoding-bech32m` folded into `encoding-bech32` (#171).** BIP-173 and
  BIP-350 are one dependency, one error type, and one code-length knob, differing only in
  a checksum constant.
- **The allocation oracle's counter is thread-scoped (#174),** so allocations made by
  other threads are no longer charged to the closure under test.
- **`zeroize_derive` moved to `[dev-dependencies]` (#171).** Nothing in `src/` derives
  `Zeroize`, so it no longer forces `syn` + `quote` + `proc-macro2` into downstream builds.


### Removed

- **`secure-gate-compat` is deleted.** The `secrecy` v0.8 / v0.10 shim crate was
  experimental, never published to crates.io, and had no known consumers — the one
  downstream tracking this branch depends on `secure-gate` alone. It cost more than it
  returned: a disproportionate share of every review, audit and release cycle went to a
  crate nobody could install.

  **Recovering it:** the crate is intact in git history and in the release tag.
  `git checkout v0.8.0-rc.12 -- secure-gate-compat` restores the last version on this
  branch, including its migration guide. The tag is pushed, so this works from any clone.
  Nothing is lost, only unmaintained.

  Removed with it: the crate's five CI lint rows, its release-profile test step, its
  `no_std` cross-build, its three MSRV check/test steps, and its Miri and fuzz-quick path
  filters. `secure-gate` itself is unchanged — the published crate's contents and API are
  untouched.


- **`InnerSecret<T>` (#172)** — `into_inner` hands back the plain value.
- **The `*_zeroizing` encoder methods (#172)** — superseded by the above.
- **`Bech32Error::ConversionFailed` and `DecodingError` (#171)** — the first was
  unreachable, and the second was a wrapper nothing produced.
- **The `encoding-bech32m` feature (#171)** — see the fold above.
- **BREAKING: `AsRef<str>` and `AsRef<[u8]>` on `EncodedSecret` (#172).** Removed with
  the rest of the #172 surface reduction but missed by this entry until now, which is
  how a downstream adopter met it without warning. `Deref<Target = str>` is the single
  accessor: `&str` coercion, `&*encoded`, inherent `str` methods and method resolution
  through the deref all still work.

  **Migration:** one pattern genuinely breaks. Deref coercion applies at a coercion site
  but does not satisfy a generic bound, so an `impl AsRef<[u8]>` parameter no longer
  accepts an `EncodedSecret` — `fs::write(path, &encoded)` being the common shape. Pass
  `encoded.as_bytes()`.


### Fixed

- **Backported the pre-publish audit fixes from `main` (#182).** Same defects, same
  branch, found by an adversarial review of the 0.9 release candidate and confirmed
  present here rather than assumed. `publish = false` had stopped at the manifest while
  the root README still listed the compat crate under "Published as" with a crates.io
  link, both READMEs and `MIGRATING_FROM_SECRECY.md` gave a `version = "0.8"` dependency
  line that cannot resolve, and `Cargo.toml` advertised a `documentation` URL on docs.rs
  that will never be built. The migration steps in `v08` and `v10` told readers to add
  `secure-gate` with `features = ["secrecy-compat"]`, which is a feature on *this* crate
  — the same class as the `secure_gate::compat::` paths rc.12 already fixed, missed in
  the steps beside them. Three intra-doc links resolved successfully to the wrong item:
  `mod.rs`'s `CloneableSecret` was labelled `secure_gate::CloneableSecret` but targeted
  compat's own marker, `v10`'s "secure-gate native" table pointed at that same compat
  trait, and `SerializableSecret`'s doc named `crate::SerializableSecret` when the
  `pub use` is `secure_gate::SerializableSecret`. `ExposeSecret`'s docs credited
  `RevealSecret` with byte-length metadata that lives on `SecretLen`. `secrecy-compat`
  was documented as "enabling" shim modules that carry no `cfg` on it. `v08` was
  described as having no const-generic arrays while implementing `DebugSecret for
  [T; N]`. The `full` feature was documented as "Everything" when it deliberately omits
  `std`. `SECURITY.md`'s `cargo test` line lacked `-p secure-gate-compat`, and its "last
  updated" stamp still read March 2026.

- **`tests/proptest_suite/` was gated on this crate's `alloc`, which `secrecy-compat`
  does not enable.** `secrecy-compat` turns on `alloc` transitively but the file's
  `#[cfg(all(…, feature = "alloc"))]` names *this* crate's feature, so
  `--features secrecy-compat --all-targets` compiled none of it and only `--all-features`
  ever did. Measured: 0 proptest cases before, 12 after. The parent module already gates
  on `secrecy-compat`, so the conjunct was pure concealment.
- **`cargo doc` builds on 1.70 again; the bech32 re-exports are split.** The #171
  backport reintroduced the grouped-`use` rustdoc ICE that `SecretLen` already hit:
  `pub use traits::{Bech32Sized, Bech32Standard};` and two more grouped re-exports made
  rustdoc 1.70 — this line's MSRV toolchain — panic resolving intra-doc links ("no
  resolution for `Bech32Sized` MacroNS"), so `cargo doc` on 1.70 has been broken since
  that backport. docs.rs builds on nightly and was never affected, which is why nothing
  noticed. The three re-exports are split into six, each with its own doc comment, and
  a `Rustdoc – builds on MSRV (1.70)` CI job now guards it with `-D warnings` (which
  also catches broken intra-doc links, previously ungated). The job is scoped to core:
  `secure-gate-compat` carries 11 pre-existing broken links and is never published.
- **`base32_error_display` / `base64_error_display` were gated on `std` (audit).** A
  three-way merge artifact from the backport: the `DecodingError::source()` tests that
  once occupied those line positions were `std`-gated and were deleted by #171, and the
  old `cfg` lines were carried onto the new function bodies. Both assert only `Display`,
  which every build implements, so feature rows without `std` were silently skipping two
  pins that still run on `main`. `hex_error_display` was unaffected.
- **`SecureEncoding` / `SecureDecoding` documentation claimed to gate the encoders
  (audit).** Neither is used as a bound anywhere in the crate. Every `To*` blanket is
  `T: AsRef<[u8]> + EncodableBytes` and every `From*Str` blanket is plain `AsRef<str>`.
  `SecureEncoding` is even implemented for `str` and `String` — exactly what
  `EncodableBytes` exists to reject — so the old wording pointed readers at the wrong
  guarantee. `EncodableBytes` now appears in the trait table as the load-bearing bound,
  and both markers are described as vestigial.
- **Stale references to types this backport removed (audit).** `SECURITY.md` still cited
  `source()` chaining on `DecodingError`; the allocation oracle still described its
  `thread_local!` cells as `const`-initialized in three places, which is true on 0.9 and
  false here.
- **Crate-level `SECURITY.md` links pointed at `main` (audit).** Six links across
  `lib.rs`, `traits/mod.rs` and `revealed_secrets/mod.rs` now target `release/0.8`,
  since that file is branch-specific. Design-record links stay on `main`: this branch
  carries those records verbatim and they describe `main`.
- **README and the `EncodedSecret` design record were incomplete (audit).** The README
  upgrade notes now list the `EncodableBytes` bound and the removal of `DecodingError`
  and `Bech32Error::ConversionFailed`; `docs/encoded_secret_deref.md` is annotated with
  its 0.8 backport, matching the newtype design records.


### Testing

- **`secrecy-compat` is gated as standalone, and stays out of `full`.** The shim is
  experimental and may yet be purged, so it has to be opt-in and has to stand on its own
  rather than lean on `default = ["alloc"]`. Both were already true — `full` forwards
  only to `secure-gate`'s own full set, and the shim builds and tests from
  `--no-default-features --features=secrecy-compat` — but nothing held them true. The
  lint row now uses that exact form, and the reason is recorded on the `full` definition
  in the manifest where someone would otherwise add it.

- **The compat lint matrix gained two rows, and the rustdoc job lost compat.** The
  matrix stopped at `full`, which does not enable `secrecy-compat`, so the shim surface
  itself and the whole feature set were never linted here; both are now covered. Two
  further rows for each serde feature alone were considered and dropped — the bug they
  would guard cannot occur on this branch, since `serde-serialize` and
  `serde-deserialize` already name `dep:serde`, and `--all-features` covers compilation.

  Compat's rustdoc is no longer gated. The bar for an experimental, never-published
  crate that may be purged is that it compiles and its tests pass, so it cannot block
  core — not that its docs are publication-clean. Core's rustdoc is still gated on 1.70.

  `main`'s companion change, running compat's runtime suites in debug rather than
  release-only, is **not** needed here — the MSRV job already runs
  `cargo +1.70 test -p secure-gate-compat --all-features`, which is the debug profile.
- **Core test and fuzz suites brought up to `main`, on this branch's toolchain.**
  405 → 422 tests. Gained `Dynamic<T>` From-impl coverage (`Box<Vec>`, `Box<String>`,
  owned values) this branch had none of; additions across the base32, hex, ct_eq and
  macros suites; `asm_dse_check` updates; proptest regression seeds; a
  `dynamic_string_no_hex` compile-fail fixture pinning that `Dynamic<String>` has no
  encoders; and updated fuzz targets. Ten files were deliberately not taken, because
  `main`'s versions carry its newer toolchain rather than new content — the inline
  `const {}` initializers (1.79+), `usize::div_ceil` (1.73+), `edition = "2024"` in
  the fuzz manifest, and this branch's `#[allow(clippy::redundant_clone)]`, which 1.70
  needs and 1.98 does not.
- **Restored `base32_impossible_block_lengths_error_and_never_panic`.** A 0.8-only
  pin: `base32ct` 0.2 panics on trailing-block lengths of 1, 3 or 6 characters, which
  is a denial-of-service path on attacker-supplied input. `main` deleted the test
  because 0.3 fixed the bug upstream, and 0.3 is edition 2024 / 1.85. The
  `encoded_len_is_decodable` guard is still live in `src/`, so the parity pass had
  briefly left a reachable panic path unpinned.
- **Restored the `SecureEncoding` / `SecureDecoding` existence pin,** widened to cover
  both markers (the original covered only `SecureDecoding`) and written alloc-free.
  `main` removed the traits and deleted their pin with them; this branch kept the
  traits, so two public, crate-root-re-exported items were left untested.

- **Payload freedom in the error types is enforced, not just documented.**
  `error.rs` has always promised that errors "never contain payload bytes, HRP
  strings, or other input-derived text". That is a security property: these
  errors are produced while parsing secret material, so a variant that captured
  its input would put decoded secret bytes into a value callers routinely log,
  bubble up with `?`, and format into panic messages. `tests/error_tests.rs` now
  applies `assert_payload_free<T: Copy + 'static>()` to all five error types, in
  both a `#[test]` and a `const _` block so it binds builds that never run the
  suite. `Copy` rejects owned payloads; `'static` rejects payloads borrowed from
  the input. A `const fn` with a non-`Sized` bound has been legal since 1.61, so
  this carries to MSRV 1.70 unchanged.

  Additionally verified on five separate feature rows — `--no-default-features`,
  `alloc`, `std`, `alloc,encoding-hex` and `full` — since a backport that only
  builds under `--all-features` is the usual way this looks green while broken.

### CI

- **This branch is scanned by CodeQL for the first time.** Code scanning ran on
  *default setup*, which analyses only the default branch and pull requests into
  it. Measured against the API: 751 analyses on `refs/heads/main`, **zero**
  referencing `release/0.8` — and pull requests into this branch received no
  CodeQL checks at all, including the one that changed 191 files across the
  repository flatten. `.github/workflows/codeql.yml` now covers push and
  pull_request on both branches. The file has to exist *here* as well as on
  `main`, because a push to this branch runs this branch's workflow file. Note
  the weekly cron does not cover this branch — GitHub raises scheduled events
  only from the default branch — so push and pull_request are its coverage.

- **A workflow that runs no jobs now fails instead of reporting success.** This
  branch's `audit.yml` carries the same two-job split as main's, both halves
  gated on `github.event_name`. Add a trigger without extending an `if:` and both
  skip — and **a workflow whose jobs all skipped reports success**, showing a
  green tick for a run that executed nothing. A `guard` job now fails when every
  result in `toJSON(needs)` is `"skipped"`.

### Documentation

- **`Error` impl availability is stated on each error type, not only in the module
  doc.** On this branch the impl **is** `std`-gated: without the `std` feature the
  type still exists and still implements `Display`, but it is not an `Error`, so
  `?` into `Box<dyn Error>` and `std::io::Error::other` will not compile. The note
  names the cause — `core::error::Error` needs Rust 1.81 and this LTS line targets
  1.70 — and points at 0.9.x, where the impl is unconditional. This is the exact
  confusion a downstream hit: the module doc mentioned it, the types did not.

- **`EncodedSecret::into_inner` documents what it costs at a public API boundary.**
  Returning the `String` from your own public function hands callers a value with
  no zeroize-on-drop and no redacted `Debug`; every later copy is an ordinary heap
  allocation this crate can no longer clear. Returning `EncodedSecret` keeps the
  protection travelling with the value, and it derefs to `str`, so read-only
  callers need no change.

- **`dynamic_newtype!`'s doc slot takes exactly one string literal.** It is matched
  as `$doc:literal`, so `concat!(...)` does not match. Documented along with
  something worse found while checking it: the failure is reported by the catch-all
  arm as *the inner type* not being one of the shaped types, when the doc argument
  is the real problem.

## [0.8.0-rc.11] - 2026-09-07

> Backported from `main` (PRs #145 and #153). Same defects, adapted to this branch: the
> `compile-fail` CI job is pinned to 1.70 rather than 1.85, `docs/security_hash_eq.md`
> does not exist here so its claim-scoping edit is omitted, and there is no
> `dynamic_string_no_hex` compile-fail test on this branch to reference.
>
> The `Added` and `Changed` entries below, the #157 fix, and the compile-fail skip
> pattern are backported from `main`'s 0.9.0-rc.8 (#155, #156, #157). Adaptations for
> this branch: `rand` 0.9 names (`TryRngCore` rather than `TryRng`) in the generated
> `from_rng`, compile-fail snapshots re-blessed on 1.70, no `dynamic_string_no_hex`
> fixture here (so the `Dynamic<String>`-has-no-hex claim stays unpinned on this
> branch), and `secure-gate-compat`'s `migration_full` test gains the `SecretLen`
> import the split requires (as do the fuzz targets). `asm_dse_check` follows both LLVM
> alias spellings for the folded newtype symbol — 1.70 emits a separate function, 1.85
> `.set`, current stable `=`. `macros_suite/newtype.rs` imports `io::Read` for
> `as_reader().bytes()` (this branch's `--all-features` MSRV step is the only CI entry
> that compiles it). `custom_inner_no_len` exercises `SecretLen` on a shaped type first
> so `-D warnings` cannot turn its import into a snapshot mismatch, and current stable
> clippy's `useless_format` is allowed on the two `EncodedSecret` tests that exercise
> the documented `format!("{}", &*encoded)` migration form. The design records
> (`docs/nominal_newtypes.md`, `docs/composability_restructure.md`) are carried over
> verbatim and describe `main`.

### Added

- **`fixed_newtype!` / `dynamic_newtype!` — nominal newtypes over `Fixed` / `Dynamic`
  (#155).** The `*_alias!` macros emit `type` aliases, so two aliases of the same shape
  are the *same* type: an encryption key and a MAC key are both `Fixed<[u8; 32]>`, and
  swapping them at a call site compiles silently. The new macros emit `struct`s instead,
  so the compiler rejects a swapped key role. This is the one class of secret-handling
  defect the alias design cannot see.

  ```rust
  fixed_newtype!(pub EncKey, 32);
  fixed_newtype!(pub MacKey, 32, "HMAC-SHA256 key. Never used for encryption.");

  fn seal(enc: &EncKey, mac: &MacKey) { /* … */ }
  // seal(&mac, &enc) does not compile.
  ```

  Syntax mirrors the alias macros (visibility forms, optional doc string), plus an
  opt-in `derive:` list — `ConstantTimeEq`, `Deserialize`, and the base-access tokens
  described below. Generated types are
  `#[repr(transparent)]` with `#[inline]` delegation — `tests/asm_dse_check.rs` now
  asserts against a newtype symbol and finds LLVM folds it into the plain-wrapper
  symbol (`.set`), i.e. byte-identical machine code. They carry every wrapper
  guarantee: zeroize on drop, `[REDACTED]` `Debug`, access only via `RevealSecret` /
  `RevealSecretMut`, and no `Deref` (so separation is total, not by-value-only).

  **`Clone` and `Serialize` are deliberately not generated.** Neither can be forwarded:
  `Fixed<[u8; N]>: Clone` needs `[u8; N]: CloneableSecret`, which the orphan rule makes
  permanently unimplementable downstream. A generated impl would have to route through
  `with_secret` and rebuild — opting the secret into cloning with no marker impl
  anywhere, spelled in one word inside a macro expansion. Since a generated newtype is
  local to the caller's crate, callers who want it write the impl by hand, where the
  decision is visible and greppable. Asking for either is a compile error carrying the
  reasoning; the hand-written pattern is a doctest on `fixed_newtype!`.

  **Inner types are matched as literal tokens.** `dynamic_newtype!(pub P, String)` and
  `(pub P, Vec<u8>)` get the full API for their shape; anything else requires an
  explicit `generic` marker (`dynamic_newtype!(pub P, generic MyStr)`) and gets the
  reduced surface — no `SecretLen`, no encoders. A bare unrecognised type is a compile
  error naming both options, rather than silently degrading. Macros match tokens, not
  resolved types, and this is true of procedural macros too (they run before type
  resolution), so the fix is to remove the silent path rather than to see through the
  alias.

  **No implicit conversion to or from the base wrapper.** Nothing generates
  `From<Fixed<[u8; N]>>` / `From<Dynamic<T>>` or `Deref`, so an alias-typed value (a
  `dynamic_alias!` that stayed a synonym) cannot flow into a newtype through `.into()`,
  and `&Newtype` never coerces to `&Wrapper`. By default the only path in or out is the
  3-tier access API — a `with_secret` round trip. Base-wrapper access is opt-in per
  newtype and split by direction: `derive: [FromWrapper]` adds `from_wrapper` (a base
  value enters the role), `derive: [IntoWrapper]` adds `as_wrapper`, `as_wrapper_mut`,
  and `into_wrapper` (material leaves toward the base), and `WrapperAccess` is both. In a
  mixed tree the base type is the pool every plain alias lives in, so `FromWrapper` on a
  boundary type accepts all of them (the source never opts in — it is just the base
  type), and `IntoWrapper` on a secret role downgrades it to the least-sensitive alias
  sharing its base. Neither token is the sufficient default more often than it looks.

  Shaped `dynamic_newtype!` constructors take `impl Into<String>` / `impl Into<Vec<u8>>`,
  so `Name::new("literal")` works and a hand-written newtype's call sites need not move.

  Design record: `docs/nominal_newtypes.md`; downstream cross-check against
  `docs/secure-gate-requested-newtyping-requirements.md` in its §8. Pinned by 17
  `trybuild` compile-fail cases including cross-role assignment (E0308), `N = 0`, a
  user-added `Drop` (E0509), the rejected `derive:` options, the absent `.into()` path
  from a base wrapper, the absent `Deref`, directional base access, and per-newtype
  `Serialize` not leaking to siblings.

- **Base32 encoding — `ToBase32` / `FromBase32Str` behind `encoding-base32` (#158).**
  Backported from `main`'s 0.9.0-rc.8. The fifth format beside hex, base64url, bech32
  and bech32m: `to_base32()` / `to_base32_zeroizing()` and `try_from_base32()`,
  blanket-implemented for `AsRef<[u8]>` and `AsRef<str>`, with `ToBase32` impls on
  `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>`, inherent `Fixed::try_from_base32` /
  `Dynamic::try_from_base32` constructors, and a new `Base32Error` (`InvalidBase32`,
  `InvalidLength { expected, got }`, also reachable as `DecodingError::InvalidBase32`).
  `fixed_newtype!` and `dynamic_newtype!` forward both directions for their byte-shaped
  arms. Included in the `encoding` and `full` meta-features.

  **One canonical form: RFC 4648 §6, uppercase, unpadded** — the shape `otpauth://` key
  URIs carry TOTP/HOTP shared secrets in, and the densest encoding that fits QR
  alphanumeric mode. Decoding is strict: lowercase, mixed case, `=` padding, whitespace,
  and impossible lengths are rejected rather than normalized. There is deliberately no
  `to_base32_lower()`. The one leniency the backend keeps is non-canonical trailing bits
  (`"MZ"` decodes to the same byte as `"MY"`), so decoding is not injective; that is
  documented on `FromBase32Str` and pinned by
  `base32_accepts_non_canonical_trailing_bits`.

  **Backend differs from `main`: `base32ct` 0.2, not 0.3.** base32ct 0.3 is edition 2024
  with `rust-version = "1.85"` and cannot build on this line's MSRV 1.70. The 0.2 line is
  edition 2021 / MSRV 1.60 and exposes the same `Base32UpperUnpadded` + `Encoding` API,
  so the port is source-identical; only the version requirement differs. A caret on
  `"0.2"` cannot resolve across the 0.2 → 0.3 semver break, so unlike `base64ct` this
  needs no exact pin. Unlike 0.3, base32ct 0.2 *does* have an `alloc` feature, which
  `alloc` now forwards via `base32ct?/alloc`.

  The traits require `alloc` (they return `String` / `Vec<u8>`), but
  `Fixed::try_from_base32` decodes into a `Zeroizing<[u8; N]>` stack buffer and works
  without it, like every other `Fixed::try_from_*`.

### Changed

- **BREAKING (pre-release): `len`/`byte_len`/`is_empty` moved from `RevealSecret`
  to a new `SecretLen` trait; `RevealSecret`/`RevealSecretMut` widened to every
  inner type (#156).** `RevealSecret` was implemented only for `Fixed<[T; N]>`,
  `Dynamic<String>`, and `Dynamic<Vec<T>>` — because it carried `len()`, which a
  generic inner type cannot answer. That narrowness broke the crate's own
  recommended opt-in pattern: the local inner newtype that
  `CloneableSecret`/`SerializableSecret` docs instruct users to define produced a
  secret that could be cloned, serialized, and zeroized but **never read** —
  `Fixed<SessionKey>` had no `with_secret`, no `expose_secret`, nothing.

  `RevealSecret` (access) and `RevealSecretMut` are now implemented for **all**
  `Fixed<T>` / `Dynamic<T>`; length metadata lives in `SecretLen`, implemented
  exactly where a length is meaningful (`Fixed<[T; N]>`, `Dynamic<String>`,
  `Dynamic<Vec<T>>`). The custom-inner-type pattern is now fully usable —
  pinned by `tests/composability.rs`; `SecretLen` staying narrow is pinned by
  `tests/compile-fail/custom_inner_no_len.rs`.

  **Migration:** call sites using `len()`/`byte_len()`/`is_empty()` on a wrapper
  add `use secure_gate::SecretLen;`. No call-site rewrites; on this repo's own
  suite every migration edit was an import line.

- **BREAKING (pre-release): wrapper encoding methods are now trait impls, not
  inherent methods (#156).** `to_hex`, `to_hex_upper`, `to_base64url`,
  `try_to_bech32`, `try_to_bech32m`, and their `_zeroizing` variants on
  `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` are now impls of the existing `ToHex`,
  `ToBase64Url`, `ToBech32`, `ToBech32m` traits (delegating through
  `with_secret`, unchanged behavior and gating). There is no coherence conflict
  with the `AsRef<[u8]>` blanket impls — the wrappers are local and deliberately
  never implement `AsRef<[u8]>`.

  This makes the encoding surface generic: `fn fingerprint<S: ToHex>(s: &S)`
  accepts `Fixed`, `Dynamic`, and any forwarding newtype — impossible with
  inherent methods, which cannot be named as a bound or forwarded generically.
  Decode constructors (`try_from_hex`, `try_from_base64url`,
  `try_from_bech32*`) remain inherent: construction needs `Self`.
  `Dynamic<String>` still has no hex encoding. On `main` that exclusion is pinned
  by the `dynamic_string_no_hex` compile-fail fixture; **this branch does not carry
  that fixture**, so the exclusion holds by construction here but is not
  regression-tested. See the note in the 0.8.0-rc.11 preamble above.

  **Migration:** add the format trait import at call sites
  (`use secure_gate::ToHex;` etc.); call syntax is unchanged.

  Design record for both changes: `docs/composability_restructure.md`.
  Backported from `main` (#156) as that document planned, so both lines expose
  the same trait shape.

### Removed

- **BREAKING: `Display` on `EncodedSecret` (#149).** `{}` on an `EncodedSecret` is now a
  compile error. The type printed `[REDACTED]` for `Debug` and the full encoded secret
  for `Display`, which is the wrong way round for accident-prevention: redacted `Debug`
  teaches a caller that the type is safe to put in a log line, and a transparent
  `Display` on that same type then punishes exactly the callers who checked.
  `tracing::info!("token: {tok}")` and `format!("{tok}")` were the realistic accidents,
  and a missing `Display` is what prevents them.

  **Scope — this closes format strings, not extraction.** `Deref<Target = str>` is
  retained, so `str::to_string()` and `.to_owned()` still yield an ordinary unzeroized
  `String`. Removing `Display` does not change that and was never going to: those are
  named, intentional extraction, and the crate stops there by design (see *Where
  accident-prevention ends*). Do not read this change as making `EncodedSecret`
  copy-proof.

  **Migration:** write `&*encoded` where you previously relied on `Display`.
  `format!("{}", &*encoded)`, `write!(w, "{}", &*encoded)`, and `encoded.as_ref()` all
  work unchanged; `AsRef<str>` and `AsRef<[u8]>` are untouched. Enforced by
  `tests/compile-fail/encoded_secret_no_display.rs`.

### Security

- **`std::io::Write` on `Dynamic<Vec<u8>>` left the secret in the outgoing buffer when
  it grew (#152).** Writing past the current capacity delegated to `Vec::write`, so the
  standard library reallocated: it copied the plaintext into the new allocation and
  handed the **old** one back to the allocator with the secret still in it. Drop later
  wiped only the new buffer, so a drop-time check reported success while a full copy of
  the secret had already been freed — recoverable from a core dump, swap, or a heap
  scrape until the allocator reused the page.

  The docs made this worse rather than flagging it: the impl was described as "a pure
  security improvement", `SECURITY.md` said `Write` "is not an exposure surface", and the
  rustdoc example started from `vec![]` — capacity zero, so the documented happy path was
  the worst case.

  `Write` now grows by hand: it allocates the larger buffer, copies, zeroizes the old one
  (contents *and* spare capacity, via `Vec::zeroize`, which does not free), and only then
  releases it. Growth stays amortized — the new capacity mirrors `Vec`'s doubling — so
  repeated writes remain linear, and the only added cost is the wipe itself. Pre-sizing
  with `Vec::with_capacity` still avoids the copy entirely and is now what the example
  shows.

  **Scope.** This covers the growth `secure-gate` performs. It cannot cover
  `with_secret_mut` / `expose_secret_mut`, which hand out `&mut Vec<T>` / `&mut String`;
  a caller's own `push` / `extend` reallocates outside this crate. That case remains a
  documented limitation, and `SECURITY.md` now separates the two instead of denying both.

  Regression test: `tests/heap_zeroize.rs::check_write_growth_orphan_zeroed` grows a
  *live* wrapper and inspects the freed page at the moment of growth. Every other check
  in that file calls `shrink_to_fit` and only ever examines the allocation Drop releases,
  which is exactly why this went unnoticed. Confirmed to fail before the fix
  (`byte at offset 0 was not zeroed before dealloc`) and pass after, in the
  `--no-default-features --features=std` configuration CI runs.

- **`InnerSecret<T>` did not implement `Clone`, so `inner.clone()` silently returned a
  bare `T` (#146).** With no inherent `Clone`, method resolution autoderefed through
  `Deref<Target = T>` and selected `T::clone`, producing an unprotected `String` /
  `Vec<u8>` / `[u8; N]` that is never zeroized — from a call site that names no
  extraction method and does not appear in an `expose_secret` or `into_inner` grep
  sweep. This was the one place where accident-prevention failed *before* a named exit:
  every other route out of an output wrapper (`*inner`, `.to_string()`, `into_inner()`)
  is something the caller asked for by name. Added
  `impl<T: Zeroize + Clone> Clone for InnerSecret<T>`, which clones the inner
  `Zeroizing<T>` so each clone is independently owned and independently zeroized on
  drop; `inner.clone()` now resolves to `InnerSecret<T>`.

  Deliberately **not** gated on `CloneableSecret`. That marker gates cloning a live
  `Fixed`/`Dynamic`; an `InnerSecret` is already past the named extraction, so gating
  here would buy no protection and would only restore the silent `T::clone`
  fallthrough for inner types lacking the marker. `EncodedSecret` is unaffected — it
  derefs to the unsized `str`, so no fallthrough was ever possible there.

  Source-compatible for callers who bound the result with inference or used it as `T`
  by deref; a caller who explicitly annotated `let x: String = inner.clone();` must now
  write `inner.to_string()` or `(*inner).clone()`.

### Fixed

- **The DSE zeroization guard was silently dead on nightly, and could assert against
  stale assembly on any toolchain** (`tests/asm_dse_check.rs`, #150). The test hardcoded
  `target/release/deps/` as the location of the `--emit=asm` output. Nightly Cargo moved
  intermediate artifacts to `target/release/build/<pkg>/<hash>/out/`, the glob found
  nothing, and the test panicked *before reading any assembly* — so for roughly two and a
  half weeks the nightly half of the DSE matrix was not checking zeroization at all. Both
  nightly jobs (ubuntu and windows) failed on `main` at the unchanged SHA `fb15c3d5`
  starting 2026-08-03; both stable jobs passed. Reproduced locally on
  `rustc 1.100.0-nightly (e71c0f1e3 2026-08-18)`.

  The quieter half of the bug was worse: when an earlier build had left an
  `asm_check*.s` in `deps/`, the glob found that **stale** file and the guard asserted
  against assembly from a different compilation — a pass that proves nothing. This was
  observed directly; the stale file from a `stable` run made the `nightly` run pass until
  it was deleted.

  Fixed by emitting to an explicit path (`--emit=asm=<path>`, a stable rustc CLI form
  that accumulates with the `--emit` flags Cargo passes itself) and deleting that path
  before the build, so the layout is never guessed and a leftover file can never be
  mistaken for the current one. The build now goes into an isolated, wiped target
  directory, because otherwise Cargo may consider the binary fresh — identical flags
  since the last run, or a warm CI cache — skip the compile, and emit nothing. A new
  assertion fails loudly if Cargo reports success but no assembly appears, so the
  degenerate case can no longer masquerade as a pass. Side benefit: the isolated tree
  builds only `asm_check`'s real dependencies rather than the workspace dev-dependencies,
  cutting the test from a full release build to roughly 10 s. Verified on nightly,
  stable, and the pinned 1.70, including back-to-back runs with identical flags.
- **`dynamic_no_deref` compile-fail snapshot mismatched under `--features=std` (#157).**
  Root cause was diagnostic, not semantic: with `std` enabled `Dynamic<Vec<u8>>`
  implements `io::Write`, so rustc appended a ``help: there is a method `by_ref` with a
  similar name`` note to the E0599 for `secret.as_ref()`, and the snapshot (blessed
  without `std`) no longer matched. The `AsRef` probe is now written through the trait
  (`AsRef::<Vec<u8>>::as_ref(&secret)`), which yields E0277 with no similar-name lookup
  — a sharper assertion of the actual property (no `AsRef` impl) and byte-identical
  output across `alloc`, `std`, and `full` on the blessing toolchain.

### Dependencies

- **`cargo audit` is clean again.** The scheduled audit had been red on this branch since
  2026-08-10. One vulnerability and three warnings, none in code this crate ships:
  `crossbeam-epoch` 0.9.18 -> 0.9.21 (RUSTSEC-2026-0204, via `criterion`, dev-only);
  `rand` 0.9.2 -> 0.9.5 and `rand` 0.8.5 -> 0.8.8 (RUSTSEC-2026-0097, unsound - patched
  at >= 0.9.3 and >= 0.8.6 respectively; the 0.9 line is a real dependency under the
  `rand` feature, the 0.8 line arrives through `proptest` and is dev-only). The
  `bincode` dev-dependency is **removed** (RUSTSEC-2025-0141, unmaintained): its only
  use was one binary-format round-trip of an inner newtype that the `serde_json`
  round-trips in the same suite already cover through the same `deserialize_seq` path.
  Docs no longer name `bincode` as the example format. Upgrading was not an option -
  the advisory lists no patched version, so `bincode` 2 carries it too.

  Lockfile regenerated with `cargo +1.70 update` per the MSRV rule in the README.

- **Two `atty` warnings remain, known and blocked by MSRV 1.70.** RUSTSEC-2024-0375
  (unmaintained) and RUSTSEC-2021-0145 (unsound) reach the graph through `criterion`
  0.4, which is dev-only and never built by consumers of this crate. `criterion` 0.5
  drops `atty`, but it needs `clap` 4, whose `anstream` stack requires `windows-sys`
  >= 0.60.2 - and every version in that range requires rustc 1.71 or newer, so it
  cannot be taken on this branch. Both findings are informational, so `cargo audit`
  exits 0 and the workflow is green. They are recorded here rather than suppressed
  with an `audit.toml` ignore; the 0.9 line, on MSRV 1.85, does not have this
  constraint.

### Testing

- **Compile-fail enforcement that the secret wrappers have no `Deref`/`AsRef`**
  (`tests/compile-fail/fixed_no_deref.rs`, `tests/compile-fail/dynamic_no_deref.rs`, #148).
  This is the crate's load-bearing "no implicit access" claim and it was previously
  asserted only in prose on the core side — `secure-gate-compat` had the equivalent
  guard, core did not. Each case pins three diagnostics: `E0614` for `*secret`, `E0599`
  for `secret.as_ref()`, and `E0308` for deref coercion at a call site wanting the inner
  type. Verified as a real guard by temporarily adding a `Deref` impl to `Fixed` and
  confirming the snapshot mismatches.
- **New `compile-fail` CI job pinned to Rust 1.70 (#148).** The trybuild snapshots assert
  compiler diagnostics, which drift on stable, so the stable jobs skipped them by name
  and the MSRV job skipped them too — each pointing at the other. The stable `test` job
  said they were "covered by local/toolchain-pinned runs"; the MSRV job said they "run in
  the stable `test` job". Both cannot be true, and neither was: no CI job ran any
  compile-fail test, so the negative API guarantees were enforced nowhere. The new job
  runs `--test compile_fail_tests` on 1.70 — this branch's pinned toolchain
  (`rust-toolchain.toml`) and the one the `.stderr` files are blessed against — so
  diagnostics are stable by construction. Confirmed empirically: all five snapshots pass
  on 1.70 and every one of them mismatches on stable. Skip lists in the stable and MSRV
  jobs are updated to include the new test names, and the MSRV job's stale claim that
  compile-fail tests run in the stable job is corrected.
- **Stable test jobs now skip compile-fail cases by name pattern** (`--skip compile_fail`,
  plus the one legacy name `serializable_secret_misuse`) instead of an enumerated list.
  The enumerated list silently fell out of sync: the eleven compile-fail cases added for
  #155/#156 would have run on stable in every matrix entry and the release-profile job,
  and eight of them mismatch on current stable (diagnostic drift only). Every core
  compile-fail test is named `*_compile_fail`, so new cases are excluded automatically;
  the 1.70 `compile-fail` job remains the enforcing run.

### Documentation

- **The crate page now lists the newtype macros.** The `lib.rs` overview ("What's
  available without `alloc`" and the module tree) named only the alias macros;
  `fixed_newtype!` and `dynamic_newtype!` are listed with a one-line contrast.
- **`SecretLen` has its own crate-level re-export doc, and rustdoc 1.70 builds again.**
  `pub use traits::{RevealSecret, SecretLen};` carried one doc comment for both; rustdoc
  1.70 — this line's MSRV toolchain — ICEs resolving intra-doc links on a grouped `use`
  re-export ("no resolution for `RevealSecret::expose_secret` MacroNS"), so `cargo doc`
  on 1.70 has been broken since the backport. docs.rs builds on nightly and was never
  affected. The re-export is split in two; the tier list stays on `RevealSecret` and
  `SecretLen` gets a short doc of its own.
- The three newtype macro modules said "Ships in 0.9.0"; they now say the macros were
  backported to this line in 0.8.0-rc.11.
- **`SecretLen` no longer describes length as safe metadata.** Its `# Security` section
  now distinguishes contents from sensitivity: for variable-length secrets the length can
  narrow a brute-force search or fingerprint an issuer, so it is metadata *about* a secret
  — validate against it, never log or persist it next to an identifier. Also notes that
  `ConstantTimeEq` on variable-length secrets is not length-hiding (`subtle`'s slice
  comparison short-circuits on length mismatch), and that the separate trait import is an
  audit marker rather than a barrier.
- **Scoped every crate-level "no `Deref`" claim to `Fixed`/`Dynamic` (#147).** The slogan had
  drifted across `lib.rs`, `SECURITY.md` (TL;DR bullet and Core Security Model table),
  `traits/mod.rs`, `traits/reveal_secret.rs`, and both READMEs, where it read as a
  crate-wide invariant. It is not: the
  output wrappers `InnerSecret<T>` and `EncodedSecret` implement `Deref` by design, as
  the `lib.rs` type-taxonomy table already stated correctly. Claim now matches code
  everywhere.
- **New "Where accident-prevention ends" section** (`lib.rs` crate docs and
  `SECURITY.md`, following the 3-Tier Access Model). States the boundary explicitly: the
  crate keeps accidents from compiling while a secret is held in `Fixed`/`Dynamic`, and
  that obligation ends at the named extraction (`into_inner`, `expose_secret`,
  `to_*_zeroizing`). Accuracy of documented behavior does not end. Spells out what the
  output wrappers still guarantee (zeroize-on-drop of the buffer they own, redacted
  `Debug`) versus what they do not (tracking copies made through `Deref`).
- **Corrected the false claim that `InnerSecret` is "the only type in this crate that
  derefs to the secret"** (`inner_secret.rs` type doc and `Deref` impl doc, `lib.rs`
  re-export doc). `EncodedSecret` derefs to `str`.
- **Documented that `Debug` redaction does not survive a deref.**
  `format!("{:?}", inner)` prints `[REDACTED]`; `format!("{:?}", &*inner)` prints the
  secret, because redaction is a property of the wrapper and not of `T`.
- **Documented `into_zeroizing()` as a `Debug` downgrade** on both `InnerSecret` and
  `EncodedSecret`. It preserves zeroize-on-drop but not redaction: `zeroize` 1.8/1.9
  derive `Debug` on `Zeroizing<T>`, so `{:?}` on the returned value can print the
  secret. Also noted that this crate does not re-export `zeroize`, so naming the return
  type requires taking a compatible `zeroize` dependency directly.

- **RustCrypto integration example on `Fixed` (#144).** Backported from `main`. The
  `Fixed` rustdoc and the crate README now show how to run a block cipher *inside* the
  wrapper —
  `block.with_secret_mut(|b| cipher.decrypt_block(GenericArray::from_mut_slice(b)))` —
  alongside the copy-out shape (`aes::Block::from(*b)`) that type inference nudges you
  toward and that leaves plaintext-equivalent bytes in an unzeroized stack value. The
  mechanism always worked; nothing pointed integrators at it. Both examples are compiled
  doctests; `aes` joins `[dev-dependencies]` pinned `=0.8.4`, matching this branch's
  exact-pin convention and the `cipher` 0.4 / `GenericArray` API they use. They sit on
  the `Fixed` struct rather than the `fixed` module header, because `mod fixed` is
  private — its `//!` docs are doctested but never rendered on docs.rs. No library API
  changed, and the `with_block_mut` sugar also floated in #144 was deliberately not
  added.
- **`RevealSecretMut` no longer advertises `len()`/`is_empty()` as coming from
  `RevealSecret`.** They moved to `SecretLen` in the backported #156 split; the trait's
  own rustdoc had been left behind.
- **Removed a self-contradiction in the backported #156 entry above.** It claimed the
  `dynamic_string_no_hex` compile-fail "now imports `ToHex` and proves the impl
  genuinely does not exist" — a sentence carried over verbatim from `main`, on a branch
  that does not carry that fixture, directly contradicting this release's own preamble.
  The entry now states that the `Dynamic<String>`-has-no-hex exclusion holds by
  construction here but is regression-tested only on `main`.
- **`docs/composability_restructure.md` records the shipped state on both lines** —
  0.9.0-rc.8 on `main` (PR #159, `f2a8f1c`) and 0.8.0-rc.11 here (PR #160, `a029bb7`) —
  instead of describing in-progress branch work.

## [0.8.0-rc.10] - 2026-07-06

### Added

- **`Fixed<[u8; N]>` deserialization now accepts byte-string input.** The
  visitor implements `visit_bytes` / `visit_byte_buf` in addition to
  `visit_seq`, so self-describing formats that encode byte arrays as byte
  strings (e.g. CBOR) round-trip. The `deserialize_seq` entry point is
  unchanged, so the wire format for non-self-describing formats (bincode) is
  unaffected. Owned buffers handed over through `visit_byte_buf` are wrapped
  in `Zeroizing` and wiped after the copy.

### Security (backport of the pre-v0.9.0 security sweep — main PR #139)

- **`no_std` support was advertised but did not exist — now real and CI-verified.**
  The crate never declared `#![no_std]`, so it unconditionally linked `std` and
  failed to build on bare-metal targets despite the `no-std` keyword/category and
  README claims. Fixed end to end: added
  `#![cfg_attr(not(feature = "std"), no_std)]`; disabled the default `std`
  feature of `subtle`; **removed `thiserror` entirely on this branch** — its
  `no_std` support requires `core::error::Error` (Rust 1.81+), above this
  branch's MSRV 1.70, so `error.rs` hand-writes `Display` and gates
  `std::error::Error` (including `DecodingError::source()`) behind the `std`
  feature; switched `rand` to
  `default-features = false, features = ["os_rng"]` (with `std_rng` moved to a
  dev-dependency for tests); removed all `String` usage from no-alloc code paths;
  gated `FromBech32Str` / `FromBech32mStr` on `alloc` (matching the other decoding
  traits — their blanket impls always returned `Vec`); and gave the internal
  `asm_check` binary `required-features = ["std"]`. A new CI job cross-builds the
  library for `thumbv7em-none-eabihf` across all no-alloc feature combinations so
  this cannot regress silently. Note: on bare metal, `from_random` additionally
  requires a user-configured `getrandom` backend (documented in lib.rs).
- **`Fixed<[u8; N]>` deserialization could leak a secret prefix through realloc.**
  The `visit_seq` visitor reserved `N` bytes but pushed unboundedly: an input
  sequence with more than `N` elements grew the `Zeroizing<Vec<u8>>` past its
  capacity, and the reallocation freed the old buffer — already holding the first
  `N` secret bytes — without zeroization, before the length check rejected the
  input. Over-length sequences are now rejected *before* the buffer can grow.
  Regression test: `fixed_deserialize_over_length_rejected`.
- **Bech32/Bech32m HRP-checked decoding no longer materializes payload bytes
  before validating the HRP.** `FromBech32Str::try_from_bech32` and
  `FromBech32mStr::try_from_bech32m` (used by `Dynamic::try_from_bech32*`)
  previously decoded the full payload into a plain `Vec<u8>` and *then* compared
  HRPs — on mismatch, the decoded secret was dropped unzeroized. The HRP is now
  validated on the checksum-verified string before a single payload byte is
  produced, matching what `Fixed::try_from_bech32*` already did. Payload
  collection is a single exact-size allocation (`byte_iter()` is an
  `ExactSizeIterator`), so no realloc copies are left behind either.

### Changed (breaking — API stabilization ahead of v0.8.0, mirrors main)

- **Error enums are build-invariant, heap-free, `Copy`, and `#[non_exhaustive]`.**
  Previously, `FromSliceError`, `HexError`, `Base64Error`, `Bech32Error`, and
  `DecodingError` changed *shape* between debug and release builds
  (`cfg(debug_assertions)`-gated variants) — downstream code matching
  `InvalidLength { expected, got }` compiled in dev and broke under `--release`.
  Now, in every build profile:
  - `InvalidLength { expected: usize, got: usize }` always carries both lengths
    (lengths are public protocol parameters; `FromSliceError`'s field `actual`
    was renamed to `got` for consistency).
  - `Bech32Error::UnexpectedHrp` and `DecodingError::InvalidEncoding` are
    fieldless — input-derived strings (received HRPs, hint text) are never
    captured, in any build. This also removes every `String` from the error
    types, making them `Copy` and `no_std`-clean.
  - All five enums and their struct variants are `#[non_exhaustive]`: variants
    and fields can be added without a semver-major bump; downstream matches need
    a wildcard arm, and length-mismatch errors can no longer be constructed
    outside the crate.
- **`RevealSecret::into_inner` bound changed from `Default` to the new
  `SentinelValue` trait — now usable for `Fixed<[u8; N]>` with `N > 32`.**
  The previous `Self::Inner: Default` bound silently made `into_inner`
  uncallable for arrays longer than 32 elements (std's `Default` limit), which
  covers common sizes such as 64-byte Ed25519 expanded keys and HMAC-SHA512
  keys — contradicting the trait docs. `SentinelValue` (exported at the crate
  root) provides the inert placeholder left behind after extraction and is
  implemented for `[T; N]` (any `N`, `T: Default`), `String`, and `Vec<T>`;
  downstream crates can implement it for custom inner types. Regression test:
  `fixed_into_inner_beyond_default_limit`.

### Documentation

- **Marker traits (`CloneableSecret`, `SerializableSecret`): documented the
  orphan-rule consequence.** Downstream crates cannot implement these markers
  for foreign types (`String`, `Vec<u8>`, `[u8; N]`), so the `cloneable` /
  `serde-serialize` features only apply to local newtype inner types. The trait
  and re-export docs now state this explicitly, explain why it is intentional
  (pre-implementing the markers for std containers would silently opt in every
  wrapped secret in a dependency graph), and show the newtype pattern.
- `SECURITY.md`: rewrote the error-metadata section for the build-invariant
  design; documented the serde over-length guard, the HRP-before-decode
  ordering, and the CI-verified `no_std` claim.
- **Inherent Rust memory-residue limitations consolidated** — README and
  `SECURITY.md` now document allocator realloc residue, `Dynamic::into_inner`
  post-transfer mutations, and process/OS mitigations (zero-on-dealloc
  allocators, Linux `init_on_free=1`, core dumps, encrypted swap) in one
  place; Finding 2 rustdoc cross-links updated accordingly.
- **Alias macros (`fixed_alias!`, `dynamic_alias!`)** — rustdoc now states they
  are type aliases, not distinct newtypes (no extra type safety vs. a manual
  `type` alias).
- **`#[must_use]`** on selected APIs so ignored `Result`s and secret wrappers
  trigger rustc warnings.

## [0.8.0-rc.9] - 2026-05-10

### Security

- **Finding 1 — `Dynamic::new_with` closure-panic leak (HIGH).** The intermediate
  buffer used by `Dynamic::<Vec<u8>>::new_with` and `Dynamic::<String>::new_with`
  is now wrapped in `Zeroizing` for the entire lifetime of the closure. A closure
  that wrote secret bytes and then panicked previously dropped a plain `Vec<u8>` /
  `String` during unwind, leaking those bytes to the heap. The fix routes through
  the existing `from_protected_bytes` swap pattern (newly added for `Dynamic<String>`
  and the `cfg` gate removed for `Dynamic<Vec<u8>>`). New regression tests
  (`check_new_with_panic_zeroed_vec` / `_string`) in `tests/heap_zeroize.rs`
  verify the buffer is zeroed via the existing `ProxyAllocator` panic-mode hook.
- **Finding 2 — `with_secret_mut` realloc threat-model gap (MEDIUM, docs-only).**
  `SECURITY.md` now documents that capacity-changing mutations through
  `with_secret_mut` / `expose_secret_mut` on `Dynamic<Vec<T>>` /
  `Dynamic<String>` cause `Vec` / `String` to free the *previous* buffer
  through the standard allocator without zeroization. Added concrete
  guidance: pre-allocate to max needed size, prefer `Fixed<[u8; N]>` for
  known-size secrets, or replace the wrapper rather than mutate in place.
  This is a fundamental limitation of standard-library collections shared
  across the ecosystem; `Fixed<T>` is exempt.
- **Finding 3 — `deserialize_with_limit` zeroization-scope misclaim (MEDIUM,
  docs-only).** The rustdoc on `Dynamic::<Vec<u8>>::deserialize_with_limit` and
  `Dynamic::<String>::deserialize_with_limit` previously suggested the
  `Zeroizing` guarantee covered the full deserialize path. It does not — only
  the post-deserialize buffer is protected; partial bytes accumulated by the
  upstream visitor on error paths are owned by the visitor and dropped as
  plain `Vec<u8>` / `String`. Docstrings now describe the zeroization
  boundary precisely; no behavior change.
- **Finding 4 — DSE workflow coverage gaps (LOW, CI-only).** The DSE
  zeroization-check workflow no longer uses `paths:` filters, so edits to
  the test or workflow itself trigger the check on every PR. The matrix now
  includes `windows-latest` (which exercises the Intel-syntax branch of the
  asm-grep test); macOS is not in the matrix because `macos-latest` is
  ARM64 and would silently skip the `cfg(target_arch = "x86_64")`-gated
  test.

### Breaking

- **`RevealSecret::len()` now returns element count.** Previously all impls returned
  `n_elements * size_of::<T>()` (bytes), which is correct only for `T = u8` and
  violates Rust's universal `len()` = element-count contract (`Vec::len`,
  `slice::len`, etc.). Fixed impls now return element count (`inner.len()` for
  `Dynamic<Vec<T>>`, `N` for `Fixed<[T; N]>`). A new provided method
  `RevealSecret::byte_len()` returns the byte size and is overridden for multi-byte
  element types. **Behavior is unchanged** for the common cases `Dynamic<Vec<u8>>`,
  `Dynamic<String>`, and `Fixed<[u8; N]>`.

### Documentation

- **`RevealSecret` type-erasure stance clarified (design note).** `Box<dyn
  RevealSecret<...>>` / `Box<dyn RevealSecretMut<...>>` are intentionally not
  supported: the scoped APIs (`with_secret` / `with_secret_mut`) are generic and
  therefore not dyn-compatible. The design decision is to keep scoped access as
  the default tier — it structurally bounds the exposure window and keeps
  `expose_secret*` calls rare and grep-auditable. A companion dyn-erased trait
  (e.g. `DynRevealSecret` using `&mut dyn FnMut`) is deferred until concrete
  type-erasure demand (plugin registries, heterogeneous secret stores) justifies
  the ergonomic and performance trade-offs (`FnOnce` → `FnMut`, no direct return
  value, dynamic dispatch overhead).
- **Post-review rustdoc polish** — `fixed_alias!` doc attribute ordering;
  `ConstantTimeEq` length-sensitivity note; decoding-trait “wrap immediately”
  guidance; `EncodedSecret` `Display` warning at module level;
  `RevealSecret::into_inner` per-impl allocation notes.

## [0.8.0-rc.8] - 2026-04-03

### Added

- `std::io::Write` impl for `Dynamic<Vec<u8>>` — streams bytes directly into the protected buffer via `with_secret_mut`. Data flows *in*; no secret exposure.
- `DynamicReader` cursor wrapper + `Dynamic::<Vec<u8>>::as_reader()` for `std::io::Read` — replaces `with_secret` + `Cursor` boilerplate. Each `read()` call goes through `with_secret` internally.
- Both gated behind the existing `std` feature. Makes secure streaming the ergonomic default.

## [0.8.0-rc.7] - 2026-03-30

**Summary:** Comprehensive rustdoc overhaul across all public types and traits; zeroizing APIs for
encoded secrets (`EncodedSecret`, trait `_zeroizing` methods, and `Fixed` / `Dynamic` delegation
via `with_secret`); RustCrypto constant-time hex/base64 backends (`base16ct`, `base64ct`); no-alloc
`Fixed::try_from_*` decoding where applicable; broader tests (including `revealed_secrets_suite`);
and v0.8-specific README/SECURITY customizations. The crate is also split into a **workspace**
(publishable `secure-gate` core + `secure-gate-compat`). **MSRV 1.70** remains a goal; see
**Fixed** and the maintainer note below for recurring dependency/resolver conflicts (`syn`, lockfile
pins, `--all-features` Bech32 naming).

### Added
- `EncodedSecret` newtype (wrapping `zeroize::Zeroizing<String>`) with redacted `Debug` (`[REDACTED]`), `Deref<Target=str>`, `AsRef<str>`, `AsRef<[u8]>`, `Display`, `into_inner()`, `into_zeroizing()`, and `new` (internal). Added under `alloc` feature.
- Zeroizing variants of encoding methods on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` (`to_hex_zeroizing`, `to_hex_upper_zeroizing`, `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, `try_to_bech32m_zeroizing`) that return `EncodedSecret` to preserve zeroization for sensitive encoded values. Plain `to_*()` methods remain unchanged for public encodings.
- Trait-level `_zeroizing` encoding APIs on existing encoding traits — added `to_hex_zeroizing` / `to_hex_upper_zeroizing` to `ToHex`, `to_base64url_zeroizing` to `ToBase64Url`, `try_to_bech32_zeroizing` to `ToBech32`, and `try_to_bech32m_zeroizing` to `ToBech32m`.
- Wrapper delegation alignment for `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` — inherent `*_zeroizing` methods now delegate through `with_secret(...)` to trait-level implementations, mirroring the non-zeroizing flow and removing duplicated conversion logic.
- Refactored owned secret wrappers into `traits/revealed_secrets/` (`inner_secret.rs`, `encoded_secret.rs`) and narrowed `traits/reveal_secret.rs` to the `RevealSecret` trait.
- Expanded zeroizing test coverage across hex/base64/bech32/bech32m, including parity vs non-zeroizing methods, invalid-HRP/error paths, bech32m oversize payload behavior, redacted `Debug`, and edge cases (empty/all-zero/single-byte payloads).
- Added `tests/revealed_secrets_suite` integration coverage for both wrappers: `revealed_secrets_suite/encoded_secret.rs` and `revealed_secrets_suite/inner_secret.rs`, wired through `tests/integration.rs`.
- Updated docs in `SECURITY.md`, `README.md`, encoding traits, and module docs with guidance on preferring zeroizing methods when the encoded form is sensitive.
- **Encoding backends replaced with RustCrypto constant-time crates** — `hex` and `base64`
  dependencies removed. Replaced by `base16ct` v0.2 (hex) and `base64ct` v1.6 (base64url), which
  provide portable constant-time encoding and decoding with no transitive dependencies and
  full `no_std` / no-alloc support.
- **No-alloc decoding for `Fixed<[u8; N]>`** — `Fixed::try_from_hex`,
  `Fixed::try_from_base64url`, `Fixed::try_from_bech32`, `Fixed::try_from_bech32m`
  now work without the `alloc` feature by decoding directly into a stack-allocated
  `Zeroizing<[u8; N]>` buffer. Blanket traits (`FromHexStr`, etc.) remain `alloc`-only.
- **`encoding-hex` and `encoding-base64` no longer require `alloc`** — encoding traits
  still require `alloc` (return `String`), but `Fixed::try_from_*` decoding is fully no-alloc.
- **`EncodedSecret::Display` doc note** — added warning that `Display` outputs the encoded
  secret content (unlike `Debug` which prints `[REDACTED]`).
- **Edge-case tests for `Fixed` encoding decoders** — added tests covering empty input, single-byte, invalid chars, padding, checksum errors, length mismatches, HRP case-insensitivity, and cross-variant rejection for hex, base64url, bech32, and bech32m.
- **`.editorconfig` and `.gitattributes`** — added project-wide editor configuration and LF line-ending normalization rules for consistent formatting across contributors and platforms.

### Documentation

- **Comprehensive rustdoc overhaul** — rewrote and expanded documentation for all public types and traits: crate-level usage guide with module structure, `Fixed<T>` and `Dynamic<T>` security models and construction guidance, `RevealSecret`/`RevealSecretMut` 3-tier access model, `CloneableSecret`, `ConstantTimeEq` (including Unicode note), encoding traits (`ToHex`, `FromHexStr`, `ToBase64Url`, `FromBase64UrlStr`, `ToBech32`, `FromBech32Str`, `ToBech32m`, `FromBech32mStr`), decoding traits, revealed secret wrappers (`EncodedSecret`, `InnerSecret`), error types with debug-vs-release security notes, and alias macros with cross-references. Each item now includes import paths, security invariants, and usage examples.
- **Module-level re-export notes** — added documentation noting that key traits and types are re-exported from the crate root for convenience.
- **README.md** — customized for v0.8 branch (rand 0.9, `OsRng`, MSRV 1.70); refined security model section to clarify explicit access requirements and timing-safe equality implementation.
- **SECURITY.md** — customized for v0.8 branch (rand 0.9, `OsRng`); clarified security model regarding explicit exposure and timing safety.

### Fixed

- **MSRV 1.70 — `syn` resolution** — Recent `syn` releases (from **2.0.117** onward) set
  `rust-version = "1.71"`, so a fresh `cargo update` can pull a `syn` that **refuses to build on
  Rust 1.70** even though this crate's declared MSRV is still 1.70. `serde_derive`,
  `thiserror-impl`, and other proc-macro crates depend on `syn`; the failure shows up as a
  resolver/build error before any crate tests run. **Mitigation:** pin **`syn = "=2.0.100"`** in
  `dev-dependencies` (alongside the existing pins for `serde_json`, `trybuild`, `tempfile`,
  `criterion`, `proptest`, etc.) and keep **`Cargo.lock` committed**. Verify with
  `cargo +1.70 test -p secure-gate --all-features --locked` after dependency churn.
- **`--all-features` — ambiguous Bech32 trait re-exports (E0659)** — Enabling
  `encoding-bech32` links in the **`bech32`** dependency crate *and* defines local submodules
  named `bech32` under `traits::encoding` and `traits::decoding`. Unqualified
  `pub use bech32::ToBech32` / `FromBech32Str` then conflicted with the extern crate. Re-exports
  now use **`pub use self::bech32::...`** so the traits always come from the in-crate modules.

> **Maintainer note — recurring "MSRV vs. latest crates.io" conflicts:**  
> Upstream crates often raise `rust-version`, adopt **edition 2024** manifests (which **Cargo
> 1.70 cannot parse**), or add transitive deps that outpace this workspace's MSRV. That shows up
> as either **"requires rustc X or newer"** (e.g. `syn`, `zmij` via `serde_json`) or **lockfile /
> manifest parse failures** (e.g. `trybuild` → `toml_parser`, `tempfile` → `getrandom 0.4`). This
> release line uses **explicit dev-dependency pins** plus a **frozen `Cargo.lock`**; CI should use
> **`--locked`** on MSRV jobs so a clean checkout matches what maintainers verified (see also
> **[0.8.0-rc.4]** — removal of nondeterministic `cargo update` on MSRV, and caps on `ryu` /
> `half`). When a pin is no longer available or security fixes require a bump, **either** relax
> the pin and re-run the full 1.70 matrix **or** document an intentional MSRV increase — avoid
> silent drift from `cargo update` alone.

### Changed
- **`ConstantTimeEq` impls now route through `expose_secret()`** (`src/fixed.rs`, `src/dynamic.rs`) — previously accessed `.inner` directly, bypassing `RevealSecret`. Now calls `expose_secret()` with a `Self: RevealSecret<Inner = T>` bound. `Clone` and `Serialize` intentionally retain direct `.inner` access to support custom wrapped types without `RevealSecret`.
- **`Dynamic` `RevealSecret` impls use `mem::take`** — `into_inner` and `expose_secret_mut` now use `mem::take` instead of manual default construction. Comments updated to reference `Default::default()`.
- Major refactor: split the project into a Cargo workspace. `secure-gate-core` is now the minimal, auditable foundation (published as `secure-gate`), while `secure-gate-compat` isolates all `secrecy` migration shims, tests, and related code.
  - **Significantly reduces the security blast radius**: the core is no longer affected by compat-specific dependencies or vulnerabilities.
  - Simplifies maintenance, CI matrices, and independent evolution of each crate.
- Purged all compat-related features, modules, tests, and code from the core crate.
- Root workspace `Cargo.toml` manages shared metadata; core now inherits `version`, `edition`, `rust-version`, etc., via `.workspace = true`.
- Cleaned up dev-dependencies (removed `secrecy-v*` pins, as they belong in the compat crate).
- Updated manifests, imports, documentation, and CI to match the new structure.

## [0.8.0-rc.6] - 2026-03-27

### Added

- **`InnerSecret<T>`** — new newtype wrapping `zeroize::Zeroizing<T>` that is returned by
  `RevealSecret::into_inner`. Provides redacted `Debug` (always prints `[REDACTED]`), read-only
  `Deref` to `T`, and an `into_zeroizing()` escape hatch to recover the underlying
  `Zeroizing<T>`. Zeroization on drop is inherited from `Zeroizing<T>`. Available as
  `secure_gate::InnerSecret`.
- **`RevealSecret::into_inner`** — consuming method that returns the inner secret wrapped in
  [`InnerSecret<T>`] (wraps `zeroize::Zeroizing<T>`), transferring the zeroization guarantee to
  the caller. Implemented for `Fixed<[T; N]>` (zero-cost, no allocation), `Dynamic<String>`, and
  `Dynamic<Vec<T>>` (small 24-byte sentinel allocation; OOM-panic-safe). Requires
  `Self::Inner: Sized + Default + Zeroize`. Use `with_secret` / `expose_secret` when borrowing
  suffices; `into_inner` is for ownership hand-off (FFI, type migration, APIs taking `T` by value).
  **Breaking change** from the initial rc: return type changed from `zeroize::Zeroizing<T>` to
  `InnerSecret<T>`.

## [0.8.0-rc.5] - 2026-03-26

### Added

- **`Fixed::new_with` constructor** (`src/fixed.rs`) — closure-based constructor that writes directly into the wrapper's storage via `FnOnce(&mut [u8; N])`, eliminating the intermediate stack copy present in `new(value)`. All library-internal construction paths updated to use it: `TryFrom<&[u8]>`, `try_from_hex`, `try_from_base64url`, `try_from_bech32*`, `from_random`, `from_rng`, and the serde `visit_seq` deserializer. `new(value)` is unchanged and remains the ergonomic default.
- **`Dynamic::new_with` on `Dynamic<Vec<u8>>` and `Dynamic<String>`** (`src/dynamic.rs`) — closure-based constructor for API uniformity with `Fixed::new_with`. Secret bytes are already heap-allocated in `Dynamic`; this method provides a consistent construction idiom across the crate. Internal decode paths (`from_protected_bytes` + `mem::swap`) are unchanged.
- **`secrecy-compat` feature flag** (`Cargo.toml`) — opt-in compatibility shim for teams migrating from `secrecy` without rewriting call sites immediately. Enables `secure_gate::compat` and keeps native secure-gate APIs unchanged.
- **Dual-version secrecy compatibility modules** (`src/compat/`) — added `compat::v10` (secrecy 0.10.1-style `SecretBox<S>`, `SecretString`, `SecretSlice`) and `compat::v08` (secrecy 0.8.0-style `Secret<S>`, `SecretString`, `SecretVec`, `SecretBox`, `DebugSecret`), including API-level docs and migration tables.
- **Shared secrecy trait surface + bridges** (`src/compat/mod.rs`) — added `ExposeSecret`, `ExposeSecretMut`, `CloneableSecret`, optional `SerializableSecret`, and `zeroize` re-export to mirror secrecy imports; also added bridge impls so native `Dynamic<String>`, `Dynamic<Vec<T>>`, and `Fixed<[T; N]>` satisfy compat traits for incremental migration.
- **Conversion paths between compat and native wrappers** (`src/compat/v10.rs`, `src/compat/v08.rs`) — added `From` conversions to move gradually from secrecy-shaped types to `Dynamic<T>` / `Fixed<[T; N]>` and back for common string/vector cases.
- **Exhaustive `secrecy-compat` migration test suite** (`tests/compat_suite/`) — restructured and massively expanded the compat test coverage into a directory-based suite integrated into `tests/integration.rs`. Replaces the two flat test files with five focused sub-modules: `v08` (smoke tests), `v10` (smoke tests), `round_trip` (exhaustive v08↔Dynamic↔v10↔Fixed cross-type conversions with ct_eq checks), `edge_cases` (ZST arrays, large payloads ≥1 MiB, empty collections, non-u8 element types, custom Zeroize-only types, clone independence, move semantics), and `examples` (canonical copy-paste migration guide with 14 self-documenting patterns).
- **Real-world migration integration test** (`tests/migration_full.rs`) — standalone harness-free binary that runs five migration stages (v08 compat, v10 compat, native types, cross-version chain, realistic application struct), prints "Migration validated ✓" on success. Run with `cargo test --test migration_full --features secrecy-compat`.
- **Property-based compat tests** (`tests/proptest_suite/proptest_compat.rs`) — proptest suite for the compat layer: value identity, Debug invariant, clone independence, and (when `ct-eq` is active) ct_eq agreement across all round-trip combinations.
- **Compile-fail enforcement for compat explicit-access semantics** (`tests/compile-fail/compat_*.rs`) — three new trybuild tests proving that `Secret<T>` has no `Deref` (E0614), no `AsRef<str>` (E0277), and that `Debug` requires `DebugSecret` opt-in (E0277); gated on `secrecy-compat` feature.
- **Fuzz targets for compat layer** (`fuzz/fuzz_targets/compat_v08.rs`, `fuzz/fuzz_targets/compat_v10.rs`) — libfuzzer targets covering all round-trip paths, value identity, Debug invariants, and mutable access for both compat generations. Added to CI fuzz matrix.
- **`dual-compat-test` feature + dual-parity test suite** (`tests/compat_dual/`) — new opt-in feature that runs identical test bodies against both the real `secrecy` crate (pinned `0.8.0` / `0.10.1`) and the `secure-gate` compat shim side-by-side. Provides machine-verified proof of drop-in compatibility. Adds `~50` tests across `parity_v08.rs` (~24 tests), `parity_v10.rs` (~25 tests), and `divergence.rs` (5 tests). All test names include a `::real_secrecy` / `::compat_shim` suffix so failures pinpoint which side diverges. API coverage verified directly against local source clones of both secrecy versions.

### Documentation

- **`MIGRATING_FROM_SECRECY.md`** — new standalone guide covering both secrecy 0.8.x and 0.10.x: import swap tables, type mapping, step-by-step native migration, all `From` conversions, bridge impl examples, and security notes for the transition period.
- **README** — "Migrating from secrecy" section added with a short pointer to `MIGRATING_FROM_SECRECY.md`. Features table: added `secrecy-compat` row.
- **SECURITY** — Feature Security Implications table: added `secrecy-compat` row with security impact and recommendation. Compat layer security note added under Module-by-Module.

### Changed

- **CI** (`.github/workflows/ci.yml`) — dedicated `lint` job runs `clippy` + doctests on three feature combos only (`--no-default-features`, `rand` no-heap, `full`); the 17-entry `test` matrix runs `cargo test --tests` only, reducing redundant work per push.

## [0.8.0-rc.4] - 2026-03-24

### Added

- **`from_rng` constructor** (`Fixed<[u8; N]>` and `Dynamic<Vec<u8>>`, `rand` feature) — fills with bytes from any caller-supplied `TryRngCore + TryCryptoRng`, returning `Result<Self, R::Error>`; useful for seeded/deterministic RNGs in tests ([#103](https://github.com/Slurp9187/secure-gate/issues/103)).

### Fixed

- **MSRV CI: removed nondeterministic `cargo +1.70 update` step** (`.github/workflows/ci.yml`) — MSRV job now uses `--locked` for all commands so it tests the committed lockfile instead of a freshly resolved graph. This prevented transitive dep upgrades (e.g. `half 2.6.0`, `ryu 1.0.23`) from silently breaking the 1.70 job.
- **MSRV transitive dep caps added** (`Cargo.toml`) — explicit `ryu = ">=1.0, <1.0.23"` and `half = ">=2.0, <2.7.1"` version caps prevent future `cargo update` runs from pulling in versions that require rustc ≥ 1.71 / ≥ 1.81 respectively.
- **Miri timeout fixed** (`.github/workflows/fuzz-miri.yml`, `tests/integration.rs`) — `proptest_suite` is now excluded under `#[cfg(not(miri))]`; proptest's 256–512 cases per test are prohibitively slow under Miri's interpreter. Miri still runs all deterministic suites (46 tests vs. 61 before). Removed `--include-ignored` from the Miri command.
- **MSRV job no longer runs `trybuild` compile-fail tests** (`.github/workflows/ci.yml`) — `trybuild` snapshot format differs between Rust 1.70 and stable (diagnostic wording changed). Compile-fail tests validate error message wording, not MSRV compatibility; they continue to run in the stable `test` job. MSRV step now passes `-- --skip fixed_alias_zero_size_compile_fail --skip serializable_secret_misuse`.
- **`trybuild` snapshots updated** (`tests/compile-fail/fixed_alias_zero_size.stderr`, `tests/compile-fail/serializable_secret_misuse.stderr`) — blessed to current stable compiler diagnostic format (new unsatisfied-trait-bound help spans, updated `E0080` wording).

> **Maintainer note — `trybuild` snapshots:** These files (`tests/compile-fail/*.stderr`) encode exact compiler diagnostic output and must be re-blessed whenever the stable toolchain changes the error format. Run `TRYBUILD=overwrite cargo test --test compile_fail_tests --features=full` to regenerate them. Do **not** bless on Rust 1.70; only bless on the same toolchain CI's `test` (stable) job uses.

## [0.8.0-rc.3] - 2026-03-24

### Changed

- **MSRV lowered to Rust 1.70** (`Cargo.toml`) to improve downstream compatibility for the `release/0.8` line.
- **Dev-dependency compatibility pins for 1.70** (`Cargo.toml` / `Cargo.lock`) — pinned test/bench stack to Rust 1.70-compatible lines (`criterion = 0.4.0`, `proptest = 1.0.0`, `serde_json = 1.0.132`, `trybuild = 1.0.81`) and regenerated lockfile.
- **LTS docs synced to MSRV 1.70** (`README.md`, `ROADMAP.md`) — updated MSRV badge/table text and lockfile regeneration guidance (`cargo +1.70 update`).

### Fixed

- **Rust 1.70 all-features build compatibility** — disambiguated trait re-export paths in `src/traits/decoding/mod.rs` and `src/traits/encoding/mod.rs` by qualifying module paths with `self::` (no API behavior change).
- **Rust 1.70 test compatibility** (`src/traits/encoding/bech32.rs`) — replaced `.div_ceil()` in a Bech32 bit-conversion test with an equivalent stable arithmetic expression.

## [0.8.0-rc.2] - 2026-03-22

### Changed

- **Proptest coverage** — added comprehensive property-based round-trip tests for `encoding-bech32` and `encoding-bech32m` in `tests/proptest_suite/encoding.rs`. This brings bech32/bech32m to the same level of randomized testing as hex and base64url, exercising arbitrary payloads and HRP values.

## [0.8.0-rc.1] - 2026-03-21

### Breaking Changes

- **Renamed `ExposeSecret` → `RevealSecret` and `ExposeSecretMut` → `RevealSecretMut` (#101)** — The two core access traits have been renamed. `RevealSecret` more accurately describes the capability ("this type supports controlled revelation of its secret contents") while keeping `expose_secret` / `expose_secret_mut` as method names preserves their warning tone for the escape-hatch paths. All method names (`with_secret`, `with_secret_mut`, `expose_secret`, `expose_secret_mut`) and all struct/macro/encoding API surfaces are **unchanged**. Only code that names the trait explicitly is affected: `use secure_gate::ExposeSecret` → `use secure_gate::RevealSecret`; `T: ExposeSecret` bounds → `T: RevealSecret`; same for the `Mut` variant. Users who only call methods via method resolution are unaffected.

- **HRP-primary Bech32/Bech32m APIs (#100)** — `FromBech32Str` / `FromBech32mStr`: primary decode is now `try_from_bech32(expected_hrp)` / `try_from_bech32m(expected_hrp)` (payload only); raw `(HRP, bytes)` is `try_from_bech32_unchecked` / `try_from_bech32m_unchecked`. `ToBech32` / `ToBech32m`: `try_to_bech32(hrp)` / `try_to_bech32m(hrp)` only (removed optional second HRP). `Fixed` / `Dynamic`: `try_from_bech32(s, hrp)` / `try_from_bech32m(s, hrp)` for validated decode; `try_from_bech32_unchecked` / `try_from_bech32m_unchecked` replace the old single-arg `try_from_bech32` / `try_from_bech32m`. Migrate: `"s".try_from_bech32()` → `try_from_bech32_unchecked()`; `try_from_bech32_with_hrp(hrp)` → `try_from_bech32(hrp)`; `try_to_bech32(hrp, None)` → `try_to_bech32(hrp)`; wrappers: `try_from_bech32_with_hrp(s, hrp)` → `try_from_bech32(s, hrp)`, `try_from_bech32(s)` → `try_from_bech32_unchecked(s)` (and Bech32m analogs).
- **Removed `ToHex::to_hex_left`** — the redacted-logging helper has been removed from the `ToHex` trait. The function allocated a full hex-encoded `String` of the entire secret and dropped it without zeroization on the truncation path, contradicting its intended "safe for logs" purpose. Callers should construct any redacted output according to their own threat model (e.g. `format!("{}…", &hex[..n])` wrapped in `zeroize::Zeroizing`).
- **Removed `ct-eq-hash` feature** — `ConstantTimeEqExt`, `ct_eq_hash`, `ct_eq_auto`, optional `blake3` and `once_cell` dependencies, `CT_EQ_AUTO.md`, and related benches/tests/fuzz targets are gone. Timing-safe equality is only [`ConstantTimeEq::ct_eq`](https://docs.rs/secure-gate/latest/secure_gate/trait.ConstantTimeEq.html) (`ct-eq`). Migrate: enable `ct-eq` and replace any `ct_eq_hash` / `ct_eq_auto` usage with `.ct_eq()`.
- **Renamed `_expect_hrp` Bech32 constructors to `_with_hrp`** — `Fixed::try_from_bech32_expect_hrp`, `Fixed::try_from_bech32m_expect_hrp`, `Dynamic::try_from_bech32_expect_hrp`, and `Dynamic::try_from_bech32m_expect_hrp` are now `try_from_bech32_with_hrp` / `try_from_bech32m_with_hrp`. The `_with_hrp` naming follows idiomatic Rust conventions (`with_capacity`, `with_header`, etc.) and avoids implying a panic on mismatch. Migrate: rename call sites; the method signatures and behavior are identical.

### Security

- **Serde visitor length error now redacted in release builds** (`src/fixed.rs`) — `serde::de::Error::invalid_length(vec.len(), ...)` embedded the actual received byte count unconditionally, inconsistent with every other length-revealing error in the codebase. In release builds the error is now `serde::de::Error::custom("decoded length mismatch")`; debug builds retain the detailed form for diagnostics.
- **Fixed critical panic-safety bug in `Dynamic<Vec<u8>>` and `Dynamic<String>` decode and deserialize paths** — `protect_decode_result` and the `core::mem::take`-from-`Zeroizing` pattern have been replaced with a `from_protected_bytes` helper (pre-alloc empty `Box` → `mem::swap` → infallible `Dynamic::from`). `Zeroizing::drop` now remains active across the only real allocation point, closing the OOM panic window that previously stripped protection. The same fix applies to both `Dynamic<Vec<u8>>::deserialize_with_limit` and `Dynamic<String>::deserialize_with_limit`. (#96)
- `Dynamic<String>` `Deserialize` now wraps the intermediate `String` in `Zeroizing` before construction, matching `Dynamic<Vec<u8>>` and `Fixed<T>`. (#97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization now reject inputs exceeding `MAX_DESERIALIZE_BYTES` (1 MiB by default). Oversized buffers are zeroized before rejection. `deserialize_with_limit` is available for custom ceilings. (#99)
- **`Fixed<T>` decoding stack residue documented** (`SECURITY.md`) — the `try_from_hex`, `try_from_base64url`, and related decoding constructors on `Fixed<[u8; N]>` use `copy_from_slice` into a stack-allocated `[0u8; N]` before moving the array into the wrapper. The intermediate stack slot is not explicitly zeroed before the move; in adversarial environments (core dumps, memory forensics) secret bytes may persist briefly on the stack. The compiler often eliminates the slot entirely in release mode. `Dynamic<T>` avoids this pattern via `from_protected_bytes` + `mem::swap` (heap-only path). Documented in `SECURITY.md` under Wrappers potential weaknesses.

### Added

- **`rust-version = "1.75"` in `Cargo.toml`** — documents the crate's MSRV. Rust 1.75 (October 2023) is the realistic floor for the current proc-macro dependency tree (`syn` 2.x, `unicode-ident`, `thiserror` 2.x all require ≥ 1.71–1.75) and provides approximately 2.5 years of toolchain coverage.
- **HRP-validating wrapper constructors** — `Fixed::try_from_bech32_with_hrp(s, hrp)`, `Fixed::try_from_bech32m_with_hrp(s, hrp)`, `Dynamic::try_from_bech32_with_hrp(s, hrp)`, and `Dynamic::try_from_bech32m_with_hrp(s, hrp)`. These enforce case-insensitive HRP matching at the wrapper level, returning `Bech32Error::UnexpectedHrp` on mismatch. The existing HRP-discarding constructors are retained but now carry a `# Warning` doc note directing security-critical callers to the `_with_hrp` variants.
- **`Dynamic<String>` allocator-level zeroization oracle** (`tests/heap_zeroize.rs`) — `check_string_zeroed` helper mirrors `check_vec_zeroed` and verifies via `ProxyAllocator` that the `String` backing buffer is fully zeroed before deallocation. Called at sizes 16 and 32 from the aggregate `all_heap_zeroed` test.
- **Generic macro test coverage** (`tests/macros_suite/fixed_generic.rs`, `tests/macros_suite/dynamic_generic.rs`) — exercises `fixed_generic_alias!` (basic instantiation at N=16/32, `size_of` check, and an explicit N=0 documentation test showing the absence of a compile-time guard) and `dynamic_generic_alias!` (Vec<u8> and String instantiation). `tests/macros_suite/mod.rs` updated accordingly.
- `std` feature: opt-in full `std` support that implies `alloc`. Use `features = ["std"]` if you need `std`-specific integrations; `alloc` (the default) remains sufficient for all current functionality.
- **Expanded zeroization integration test coverage** (closes #94):
  - `Fixed<[u8; N]>` tested for N = 8, 16, 32, 64, 128 via a parameterized macro; all cases use `core::hint::black_box` to prevent LLVM from eliding the zeroization write.
  - Pre-drop mutation tests for `Fixed<T>`: covers `with_secret_mut`, `expose_secret_mut`, custom `Zeroize` types, and scoped-access-then-drop patterns.
  - `Dynamic<[u8; N]>` heap zeroization verified at the allocator level for N = 16, 32, 64, 128 via `ProxyAllocator`.
  - `Dynamic<Vec<u8>>` backing-buffer zeroization verified for the same sizes with fill → `shrink_to_fit` → drop sequences.
  - Mutation sequence tests for `Dynamic<Vec<u8>>` and `Dynamic<String>` covering `push`, `truncate`, `extend_from_slice`, `shrink_to_fit`, and `with_secret_mut` before drop.
  - Spare-capacity zeroization tests for both `Dynamic<Vec<u8>>` and `Dynamic<String>`.
  - Scoped `with_secret_mut` + drop tests for `Dynamic<Vec<u8>>`.
  - `heap_zeroize.rs` refactored to a single aggregate `#[test]` (`all_heap_zeroed`) eliminating race conditions with the global `ProxyAllocator` state under parallel test execution.
  - All new tests run cleanly under `cargo test --no-default-features`, `cargo test --release --features alloc`, and `cargo +nightly miri test --features alloc`.
- Added ASan CI job (`asan-heap`) for heap zeroization verification using `cargo +nightly test --features alloc --test heap_zeroize -Z build-std`.

### Fixed

- **`rand` feature no longer forces `alloc`** (`Cargo.toml`) — `rand?/alloc` has been removed from the `rand` feature. `Fixed::from_random()` only uses `OsRng::try_fill_bytes` on a stack array and requires no heap allocation; `rand` now works in pure `no_std`/`no_alloc` builds for `Fixed<T>`. `Dynamic::from_random()` continues to work when `alloc` is also active, since `Dynamic<T>` already requires `alloc` independently.
- **`tests/heap_zeroize.rs` hardened against silent false negatives and gate leakage** — test-only improvements, no library behavior changes: (1) `check_vec_zeroed` and `check_string_zeroed` now `assert_eq!(capacity, size)` after `shrink_to_fit` — without this, an allocator that rounds up capacity silently bypasses the proxy check producing a false negative; (2) `with_proxy_check` now uses a `CheckGuard` RAII struct to ensure `CHECKING` is cleared even when the closure panics — previously a panic left the gate open during stack unwinding; (3) all four helper closures now call `drop(secret)` explicitly to make drop timing clear and refactor-safe; (4) `Dynamic<String>` size coverage expanded from 2 to 4 sizes (16/32/64/128) to match `Dynamic<Vec<u8>>`; (5) Vec and String checks now interleaved in a `for size in [16, 32, 64, 128]` loop that structurally enforces size parity.
- **Wrong feature gate on `fixed_deserialize_wrong_length` test** (`tests/serde_suite/deserialize.rs`) — the test was gated `#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]`; hex encoding has no relationship to serde deserialization length checking. Corrected to `#[cfg(feature = "serde-deserialize")]` so the error path (including `Zeroizing<Vec<u8>>` drop on length mismatch) is exercised in minimal serde-only feature configurations.
- **`static` secrets + `panic = "abort"` footguns documented** (`SECURITY.md`) — `Fixed::new` is `const fn`, so `static SECRET: Fixed<...> = Fixed::new([...])` compiles silently but is never zeroized (Rust does not invoke `Drop` on program-scope statics). Additionally, `panic = "abort"` builds skip all `Drop` impls on panic, meaning secrets in scope at the time of a panic are not cleared. Both limitations are shared by the broader `zeroize` / `secrecy` ecosystem; they are now documented under _Wrappers — Potential weaknesses_ with concrete mitigation notes.
- **MSRV CI job** (`.github/workflows/ci.yml`) — runs `cargo +1.75 check` with default features and with `--features=full` on every push and PR. Previously, `full` was excluded from MSRV because `ct-eq-hash` pulled in `blake3` → `constant_time_eq` (edition2024). That feature has been removed.
- **Weak-dependency feature syntax throughout `Cargo.toml`** — every feature entry of the form `pkg/feature` where `pkg` is an optional dependency declared with `dep:` syntax has been changed to `pkg?/feature`. Without `?`, Cargo rejects the activation on MSRV toolchains because the optional dep has no implicit feature name. Affected entries: `rand?/alloc`, `hex?/alloc`, `base64?/alloc`, `bech32?/alloc`, `serde?/alloc`. The non-optional `zeroize/alloc` is unaffected.

### Changed

- **Encoding exposure model documented** (`README.md`, `SECURITY.md`, `src/traits/encoding/`) — `README.md` Encoding section rewritten to match the Equality section's upfront bullet style: three access patterns (direct method, `with_secret` closure, `expose_secret` escape hatch) with security trade-offs and audit-greppability callouts; full method reference table with fallible column and `_with_hrp` preference for Bech32; consolidated audit grep command; decode-side wrap-immediately note. Stale/incorrect "must call `expose_secret` first" claim removed from `base64_url.rs` module doc. "Audit visibility" security note added to `hex.rs`, `bech32.rs`, and `bech32m.rs`. `SECURITY.md` Encoding/Decoding mitigations block updated with exposure contract and audit grep caveat.
- **Proptest case counts raised to 256 with boundary strategies** (`tests/proptest_suite/`) — all `ProptestConfig::with_cases` overrides raised from 30/50 to 256. Variable-length vector arguments in `ct_eq_symmetric`, `dynamic_hex_roundtrip`, `dynamic_b64_roundtrip`, and `serializable_vec_roundtrip` now use `prop_oneof!` to guarantee empty, single-byte, and max-size inputs on every run rather than relying on random chance to hit them.
- **`serializable_secret_misuse` compile-fail test re-enabled** (`tests/compile_fail_tests.rs`, `tests/compile-fail/`) — the test was commented out due to a stale `.stderr` snapshot referencing `zeroize::DefaultIsZeroes` (removed in v0.8.0) and because `BadSecret` lacked a `Zeroize` impl, causing the compile error to land at `Dynamic::new()` rather than at `serde_json::to_string()`. Fixed by deriving `Zeroize` on `BadSecret` so construction succeeds and the error is correctly about `SerializableSecret` not being satisfied — the intended security boundary. Snapshot regenerated; test re-enabled with `#[cfg(not(miri))]` (same pattern as the sibling `fixed_alias_zero_size_compile_fail` test).
- **`fixed_generic_alias!` implementation notes rewritten** (`src/macros/fixed_generic_alias.rs`) — the previous note inaccurately referred to "a compile-time zero-size guard inherited from `Fixed<[u8; N]>`" that does not exist for generic aliases. The note now explains that `N=0` cannot be rejected at macro-invocation time (unlike `fixed_alias!`), that `SecretBuffer::<0>` compiles to a zero-byte type with no cryptographic utility, and directs callers to validate `N > 0` in their own tests.
- **`partial_eq_fallback` test renamed** (`tests/ct_eq_suite/basic.rs`) — renamed to `manual_comparison_without_ct_eq_feature` and given an explicit comment warning that the comparison is non-constant-time and that `ct-eq` + `ConstantTimeEq` should be used for security-sensitive equality.
- **`Bech32Error::ConversionFailed` documented as currently unreachable** (`src/error.rs`) — the variant is never produced: `.byte_iter()` on a successfully-validated `CheckedHrpstring` is infallible in the `bech32` crate; any bit-conversion failure surfaces as `OperationFailed` during the `CheckedHrpstring::new()` call. The variant is retained as public API for forward compatibility.
- **`Bech32Large` capacity documentation corrected** — all inline docs stated "~3.2 KB raw data"; the correct figure is ~5 KB (5,115 bytes maximum payload). Updated in `src/traits/encoding/bech32.rs`, `src/traits/encoding/bech32m.rs`, and `src/traits/decoding/bech32.rs`.
- **README serde section scoped** — the "no temporary string buffers" claim now explicitly excludes `Dynamic<String>`, which delegates deserialization to serde internals that may allocate non-zeroized intermediate buffers. `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` retain the guarantee. This scoping was subsequently resolved: `Dynamic<String>` deserialization now wraps its buffer in `Zeroizing` (#97), so the limitation no longer applies.
- **`cloneable_secret_works` extended** (`tests/core_tests.rs`) — wrapper-level `Fixed<CloneKey>` clone independence test added: creates a `Fixed<CloneKey>`, clones it, drops the original (triggering zeroization of its `Vec<u8>` backing), and drops the clone. Both sequential drops succeeding without panic proves the clone owns independent heap memory.
- **`try_from_bech32` / `try_from_bech32m` constructors now document HRP discard** — existing `Fixed` and `Dynamic` wrapper constructors carry a `# Warning` doc note directing security-critical callers to the HRP-validating variants (then named `_expect_hrp`, now renamed to `_with_hrp`).
- Version bump from 0.8.0-alpha.1 to 0.8.0-rc.1.
- **Breaking**: The `no-alloc` feature has been removed. To build without heap allocation (`Fixed<T>` only, embedded / pure `no_std`), use `default-features = false`. This matches the idiomatic Rust pattern used by `zeroize`, `serde`, `rand`, and others.
- The `compile_error!` guard that prevented `alloc` and `no-alloc` from being enabled simultaneously has been removed along with `no-alloc`.
- `heap_zeroize.rs` tests are skipped under Miri (`#![cfg(not(miri))]`) due to fundamental incompatibility between `#[global_allocator]` and Miri's Stacked Borrows model; heap zeroization is still verified in normal CI and under ASan.
- `compile_fail_tests.rs` trybuild test is skipped under Miri (`#[cfg(not(miri))]`) since compile-fail diagnostics are not relevant to runtime UB detection.

### Migration

```toml
# Before (0.8.0-alpha.1)
secure-gate = { version = "0.8", default-features = false, features = ["no-alloc"] }

# After
secure-gate = { version = "0.8", default-features = false }
```

```rust
// ct-eq-hash removal (if you used the old feature)
// Before
// secret_a.ct_eq_hash(&secret_b);  // or ct_eq_auto(...)
// After — enable `ct-eq` and use deterministic comparison:
secret_a.ct_eq(&secret_b);
```

## [0.8.0-alpha.1] - 2026-03-16

**Major breaking alpha release + critical security fix**

### Security

- **CRITICAL: Fixed zeroize-on-drop security flaw** (affects all versions 0.1.0–0.7.0-rc.15)  
  **Issue**: Despite documentation claiming "secrets are zeroized on drop", no `impl Drop` existed — only the empty `ZeroizeOnDrop` marker trait. Secrets were **never wiped** automatically on drop, creating a false sense of security.  
  **Impact**: All users relying on the documented guarantee had secrets persist in memory after drop, potentially exposing sensitive data to memory dumps, swap files, or other processes.  
  **Root cause**: Rust's E0367 rule prevents `Drop` impls with bounds stricter than struct bounds. The optional `zeroize` feature created conflicting bounds.  
  **Fix**: Made `zeroize` mandatory (no feature gate), added `T: Zeroize` bounds to struct definitions, and implemented real `Drop` handlers that call `zeroize()`. Zeroization is now guaranteed.  
  **Migration**: Users wrapping non-zeroizable types must implement `Zeroize` on them. Most crypto types already implement `Zeroize` out of the box.
- **All previous versions yanked**: 0.1.0 through 0.7.0-rc.15 were permanently yanked from crates.io on 2026-03-16 due to the above flaw.

### Breaking Changes

- `zeroize` is now a **required dependency** — no feature gate.
- `Fixed<T>` now requires `T: Zeroize`; `Dynamic<T>` requires `T: ?Sized + Zeroize`.
- Removed `zeroize`, `insecure`, `secure`, and `std` feature aliases entirely.
- `default` is now `["alloc"]` — users who had `features = ["secure"]` can drop it (already included by default).
- `no-alloc` builds remain possible for `Fixed<T>` (zeroize uses `default-features = false`).

### Added

- **Zeroize integration test suite** (`tests/zeroize_tests.rs` rewrite, issue #93)  
  Eight deterministic tests adapted from upstream RustCrypto/zeroize patterns
  (`zeroize/tests/zeroize.rs`, `zeroize/tests/zeroize_derive.rs`):
  - `fixed_direct_zeroize` — explicit `.zeroize()` zeroes `Fixed<[u8; 32]>` contents; verified via `expose_secret()`
  - `fixed_zeroize_on_drop` — `PanicOnNonZeroDrop` sentinel confirms `Fixed::drop` calls `zeroize()` before inner `Drop` runs; no `unsafe`, Miri-clean
  - `fixed_needs_drop` — `core::mem::needs_drop::<Fixed<[u8; 32]>>()` proves a real `Drop` glue destructor exists (would have returned `false` in all pre-0.8.0 versions — single-line regression proof for issue #92)
  - `dynamic_direct_zeroize_vec` / `dynamic_direct_zeroize_string` — `.zeroize()` empties the heap contents of `Dynamic<Vec<u8>>` and `Dynamic<String>`
  - `dynamic_spare_capacity_vec_zeroized` — `PanicOnNonZeroDrop` + `set_len` restore pattern verifies `Vec::zeroize()` byte-zeroes spare capacity (memory beyond `len` but within `cap`) via `with_secret_mut`
  - `dynamic_needs_drop` / `dynamic_needs_drop_string` — confirms real destructors exist for both heap variants
- **Heap-level zeroize verification** (`tests/heap_zeroize.rs`, issue #93)  
  Dedicated integration test binary with a `ProxyAllocator` (adapted from upstream
  `zeroize/tests/alloc.rs`) that intercepts OS deallocations and asserts all bytes of a
  `Dynamic<[u8; 64]>` backing allocation are zero before the memory is freed. Uses an
  `AtomicBool` guard to confine the assertion to the test's lifetime, preventing false
  positives from unrelated test-harness allocations of the same size.
- **Test suite reorganized** into domain-based directory suites (`ct_eq_suite/`,
  `encoding_suite/`, `serde_suite/`, `macros_suite/`, `proptest_suite/`) compiled into a
  single `integration` binary. Standalone binaries (`core_tests`, `error_tests`,
  `no_alloc_tests`, `zeroize_tests`, `heap_zeroize`, `compile_fail_tests`) are each
  auto-discovered by `cargo test --tests`. Replaced all old monolithic test files (`tests/codec/`,
  `tests/ct_eq_auto.rs`, `tests/ct_eq_tests.rs`, `tests/proptest_tests.rs`, `tests/serde/`,
  `tests/macros/`, `tests/insecure_tests.rs`).
- `**tests/common.rs`\*\*: shared helper module with `assert_redacted_debug` and
  `RevealSecret`/`RevealSecretMut` re-exports available to all suite sub-modules.
- **Bech32/Bech32m error-path test coverage** (`tests/encoding_suite/bech32.rs`): six new
  tests trigger actual `Bech32Error` variants through encode/decode calls — invalid HRP
  encoding, malformed string decoding, and decode-side HRP validation (happy path and
  mismatch) for both `bech32` and `bech32m`.
- **Fuzz targets**: new `fuzz/fuzz_targets/encoding.rs`, `serde.rs`, and `ct_eq.rs` covering
  encoding round-trips for all four formats, serde serialize/deserialize, and constant-time
  equality. Expanded `expose.rs`, `mut.rs`, `parsing.rs`, and `fuzz/src/arbitrary.rs`.

### Fixed

- Updated trybuild snapshots to resolve CI mismatches for all feature configurations.
- `**benches/ct_eq_auto.rs`\*\*: Wrapped all inputs outside `iter` in `std::hint::black_box()` to prevent constant-folding (matches fix already applied in `fixed_vs_raw.rs`). Corrected four inverted benchmark names where `_force_ct_eq`/`_force_hash` labels contradicted the actual threshold path taken (`ct_eq_auto` selects `ct_eq` when `len ≤ threshold`, `ct_eq_hash` when `len > threshold`). Collapsed duplicate `criterion_main!` pair into a single `#[cfg(feature = "ct-eq-hash")]` call.
- `**benches/ct_eq_hash_vs_standard.rs**`: Same `black_box()` fix on inputs. Added missing top-level imports (`ConstantTimeEq`, `ConstantTimeEqExt`, `Fixed`, `Dynamic`) — the bench previously failed to compile under `--features ct-eq-hash,alloc,rand`. Removed a redundant outer `#[cfg(feature = "ct-eq-hash")]` wrapping an already-specific inner `#[cfg(all(...))]`; collapsed duplicate `criterion_main!`.
- `**benches/serde.rs**`: Removed unused `extern crate alloc;` and corrected run command to `--features serde`. Added `#[derive(zeroize::Zeroize)]` to the local helper types (`SerializableArray32`, `SerializableVec`, `SerializableString`) — without it they could not be wrapped in `Fixed<T>`/`Dynamic<T>` (both require `T: Zeroize`), so the bench never exercised wrapper serialization at all. Added `Fixed<SerializableArray32>`, `Dynamic<SerializableVec>`, and `Dynamic<SerializableString>` serialize benchmarks alongside the existing newtype/raw comparisons, confirming zero-overhead delegation. Consolidated scattered local `use` statements into a single top-level import; fixed `.clone()` calls on non-`Clone` types. Moved 1 MB fixture allocation outside `iter()` so large benchmarks measure serialization rather than alloc + 2 × 1 MB `zeroize-on-drop` per sample.

### Changed

- Zeroization is no longer optional — always enabled and enforced.
- Documentation updated throughout to reflect mandatory zeroize requirement.
- `alloc` feature now enables `zeroize/alloc` for full spare-capacity wiping in `Dynamic<Vec<T>>`/`Dynamic<String>`.
- `**CT_EQ_AUTO.md**`: Refreshed all performance figures from a clean-machine run after the `black_box` fixes. Key corrections: 32 B ratio 1.7× → 2.3× (`ct_eq` ~~127 ns, `ct_eq_hash` ~288 ns); 100 KB figures reflect the permanent increase from `zeroize-on-drop` overhead (~~169 µs vs ~~565 µs, ~3.3×, not the pre-zeroize 6.5×); raw hash overhead corrected to ~59–75 ns; caching note now distinguishes 32 B cache miss (~~6%) from 1 KB alloc+zeroize cost (~70%); threshold crossover confirmed closer to 64 B; outlier ceiling ≤8% → ≤20%.

### Migration

- Update code to satisfy `T: Zeroize` (most real secrets already do).
- Replace any remaining optional-zeroize assumptions with mandatory behavior.

### CI / Dev

- CI matrix (`ci.yml`, `test_all.sh`) expanded: per-format encoding isolation configs added
  (`encoding-base64`, `encoding-bech32`, `encoding-bech32m`, `encoding-bech32 + bech32m`);
  `alloc` added to all `ct-eq`/`ct-eq-hash` entries so `Dynamic`-backed tests run; `rand`
  label corrected to reflect it always enables `alloc` via its feature graph.
- `fuzz-miri.yml`: `--skip` updated from stale `serde_core_without_marker_compile_fail` to
  `serializable_secret_misuse` (test renamed in refactor); the old name was a silent no-op
  that left the trybuild subprocess test unguarded under Miri.
- `tests/compile_fail_tests.rs`: `serializable_secret_misuse` now gated on
  `#[cfg(all(feature = "alloc", feature = "serde-serialize"))]`; previously triggered
  irrelevant missing-feature diagnostics under `--no-default-features`.

## [0.7.0-rc.1 through 0.7.0-rc.15] - YANKED (2026-03-16)

**All 0.7.0 release candidates were permanently yanked** from crates.io due to the critical zeroize-on-drop documentation flaw described in 0.8.0.  
These versions are no longer available and the repository was made private shortly after.

The following changes were developed during the 0.7.0-rc period (preserved for historical reference):

### Added

- **Polymorphic access traits**  
  `RevealSecret` and `RevealSecretMut` traits provide generic, zero-cost access with metadata (`len()`, `is_empty()`) without exposing contents. Implemented for both `Dynamic<T>` and `Fixed<T>`.
- **Timing-safe equality**  
  `ConstantTimeEq` trait (`ct-eq` feature) with `.ct_eq()` methods on `Fixed<[u8; N]>` and `Dynamic<T: AsRef<[u8]>>`.
- **Fast probabilistic equality for large secrets**  
  `ConstantTimeEqExt` trait (requires `ct-eq-hash` feature) extends `ConstantTimeEq` with methods for fast probabilistic equality using BLAKE3 hashing. Includes `ct_eq_hash()` for direct hash comparison and `ct_eq_auto()` for smart hybrid selection. Centralized threshold logic with default 32-byte crossover point.
- **Configurable decode priority in `try_decode_any`**  
  Added optional `priority: Option<&[Format]>` parameter for customizable decode order. Backward compatible with default (Bech32 → Hex → Base64url).
- **Enhanced decoding errors with hints**  
  `DecodingError` variants include hints (e.g., attempted formats) in debug builds only.
- `alloc` and `no-alloc` features for explicit heap control.
- `secure` includes `alloc` by default.
- `std` feature depends on `alloc`.
- **Per-format encoding/decoding traits** (orthogonal `ToHex`/`FromHexStr`, etc.)
- **Opt-in cloning & serialization** (`CloneableSecret`, `SerializableSecret` markers)
- **Secure random generation** (`from_random()` using `OsRng`)
- **Fallible fixed-size construction** (`TryFrom<&[u8]>` with `FromSliceError`)
- **Centralized errors** via `thiserror`
- Additional alias macros

### Changed

- **Error hardening with debug/release split** — detailed info in debug, generic in release.
- Testing & CI improvements (`trybuild`, serde fuzz, full feature matrix)
- Documentation overhaul (`SECURITY.md`, README, rustdoc)
- Serde support split into `serde-deserialize` and `serde-serialize` (gated by marker)

(Older versions below were also yanked but are preserved for history.)

## [0.6.1] - 2025-12-07 (yanked)

### Security

- Removed `into_inner()` from main wrappers (closes security bypass)
- Removed `finish_mut()` from heap types (bypassed exposure gate)

### Added

- Ergonomic RNG conversions (`FixedRng<N>` → `Fixed`)
- Convenience random generation methods

### Changed

- Macro visibility now requires explicit `pub` (no automatic fallback)

### Fixed

- Macro recursion in `dynamic_generic_alias!`

## [0.6.0] - 2025-12-06 (yanked)

### Breaking Changes

- Removed `Deref`/`DerefMut`, made inner fields private
- Removed inherent conversion methods (now trait-based)
- Replaced `RandomBytes<N>` with `FixedRng<N>`
- Removed `serde` feature (now gated by marker)
- Switched RNG to direct `OsRng`

### Added

- `len()`/`is_empty()` on fixed arrays
- Compile-time negative impl guard
- Direct `OsRng` usage

### Fixed

- Lifetime issues in RNG
- `ct_eq` bounds

### Performance

- Direct `OsRng` improved keygen throughput 8–10%

## [0.5.10] - 2025-12-02 (yanked)

### Added

- `HexString` and `RandomHex` newtypes
- `PartialEq`/`Eq` for `Dynamic<T>`
- `RandomBytes<N>` newtype
- `random_alias!` macro
- Paranoia test suites

### Changed

- Renamed randomness methods to `.new()`
- Updated doc examples

### Fixed

- Privacy/import issues
- Doc-test failures
- Test assertions
- Macro expansion/orphan rules

## [0.5.9] - 2025-11-30 (yanked)

### Security & API Improvement

- All conversion methods now require explicit `.expose_secret()`

## [0.5.8] - 2025-11-29 (yanked)

### Added

- Optional `conversions` feature for `.to_hex()`, `.to_base64url()`, etc.

## [0.5.7] - 2025-11-27 (yanked)

### Added

- `rand` feature with `SecureRandomExt::random()`

### Documentation

- Complete rustdoc overhaul

## [0.5.6] - 2025-04-05 (yanked)

### Added

- Idiomatic `.into()` conversions for `Dynamic<T>`

## [0.5.5] - 2025-08-10 (yanked)

### Changed

- Renamed `view()`/`view_mut()` → `expose_secret()`/`expose_secret_mut()`

## [0.5.4] - 2025-11-23 (yanked)

### Added

- `AsRef<[u8]>` / `AsMut<[u8]>` for `Fixed<[u8; N]>`

## [0.5.3] - 2025-11-24 (yanked)

### Changed

- Documentation polish
- Fixed relative changelog link

## [0.5.2] - 2025-11-24 (yanked)

### Added

- Idiomatic `From` / `.into()` for `fixed_alias!` types

### Changed

- Removed inherent impls from macro (now generic)

## [0.5.1] - 2025-11-23 (yanked)

### Added

- `secure!`, `secure_zeroizing!`, `fixed_alias!`, `dynamic_alias!` macros
- `from_slice()` and `From<[u8; N]>` on aliases
- `finish_mut()` emphasis
- Macro test suite

### Changed

- `fixed_alias!` emits only alias; methods via generic impls

### Fixed

- README accuracy on zeroize
- Orphan rule violations
- Privacy/feature-gating

## [0.5.0] - 2025-11-22 (yanked)

### Breaking Changes

- Replaced `SecureGate<T>` with `Fixed<T>` and `Dynamic<T>`
- Removed `ZeroizeMode`, manual wiping, password specializations, `unsafe-wipe`

### Added

- Zero-cost fixed-size secrets
- `Deref`/`DerefMut` ergonomics
- Macros for constructors/aliases
- `into_inner()`, `finish_mut()`
- `Clone` for `Dynamic<T>`

### Fixed

- No unsafe when zeroize off
- Full spare-capacity wipe
- Consistent API

### Improved

- Modular structure
- Unit tests

## [0.4.3] - 2025-11-20 (yanked)

### Fixed

- Documentation mismatch

## [0.4.1] - 2025-11-20 (yanked)

### Added

- Configurable `ZeroizeMode` enum
- New constructors with modes

### Changed

- Unified zeroization through `Wipable` trait

### Fixed

- Full wiping for empty allocated vectors
- Clone preserves mode

## [0.4.0] - 2025-11-20 (yanked)

### Breaking Changes

- Unified under `SecureGate<T>`

### Added

- `SG<T>` alias
- `Zeroizing` for fixed-size

### Deprecated

- Old names

## [0.3.4] - 2025-11-18 (yanked)

### Documentation

- Updated README

## [0.3.3] - 2025-11-18 (yanked)

### Added

- Direct exposure methods on password types

## [0.3.1] - 2025-11-17 (yanked)

### Changed

- Renamed `SecurePasswordMut` → `SecurePasswordBuilder`

## [0.3.0] - 2025-11-13 (yanked)

- Initial public release

## [0.1.0 - 0.2.3] - 2025-11-15 / 2025-11-16 (yanked)

Crates.io releases from closed development before this changelog existed (`0.1.0` through `0.2.3`). No per-version notes were kept. All yanked (see bulk yank notice for `0.1.0`–`0.7.0-rc.15` elsewhere in this file). **0.1.0** published 2025-11-15; **0.2.3** (last in span) published 2025-11-16.
