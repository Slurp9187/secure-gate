# Plan: retire the `*_alias!` macros

| | |
|---|---|
| **Status** | **Implemented** on `claude/alias-macros-necessity-i3gtge` (PR #201) and `claude/alias-macros-necessity-0.8` (PR #202). Written against `0.9.0-rc.9` (`main`) and `0.8.0-rc.12` (`release/0.8`). Review rounds since then corrected several claims in this document; where it and the code disagree, the code and the CHANGELOG win |
| **Scope** | Remove the four `*_alias!` macros; reject a zero-sized `Fixed` at construction; add `fixed_newtype!(.., generic T)`; backport all three to the 0.8 line |
| **Breaking** | Yes, twice — the macros are gone, and `Fixed<[u8; 0]>` no longer constructs. Both lines are pre-release |
| **MSRV** | Unchanged: 1.85 on `main`, 1.70 on `release/0.8`. The zero-size guard is spelled as an associated `const` so one hunk builds on both |
| **Question that started it** | Coding agents consistently reach for `*_newtype!` over the alias macros. Do the alias macros earn their place at all? |

## Context

`secure-gate` ships two macro families for naming secrets. `fixed_newtype!` / `dynamic_newtype!`
generate `#[repr(transparent)]` structs: distinct nominal types the compiler keeps apart.
`fixed_alias!`, `dynamic_alias!`, `fixed_generic_alias!`, `dynamic_generic_alias!` generate a
single `type` line each. Three of the four add only an auto doc string over what a user would
write by hand; `fixed_alias!` also adds a const-eval guard rejecting `N = 0`.

The question raised: coding agents consistently choose the newtype macros, so do the alias
macros earn their place? Four decisions were taken in discussion, all user-confirmed:

**1. Remove all four alias macros** and teach a plain `type` alias instead.

- The macro shape is the misreading mechanism. A macro exported by a security crate reads as
  a guarantee. The README called them "typed newtype wrappers" and "Type-safe wrappers" from
  0.5.1 (2025-11-23) until `fe93540` (2026-05-13), whose message records that downstream users
  relied on that reading. The one documented downstream failure
  (`docs/design/secure-gate-requested-newtyping-requirements.md`: 34 aliases collapsing to
  8 types, `FileId` and `PublicId` the same type on adjacent lines) happened under these
  macros. Nobody misreads `pub type FileId = Dynamic<String>;`.
- The case for aliases survives; only the spelling changes. The rc.9 "when an alias is the
  right reach" prose (`e0da564`) holds verbatim for `type`. R6 in the design record
  (coexistence) is satisfied identically by `type`.
- The macros are dominated on every axis. Newtypes are byte-identical in codegen
  (`tests/asm_dse_check.rs`), same syntax, strictly safer. For the residual case where
  interchange with the base type is wanted, one line of vanilla Rust is shorter than the
  macro call.
- Both lines are pre-release (`0.9.0-rc.9`, `0.8.0-rc.12`); precedent is outright removal
  with a long-form CHANGELOG entry and migration recipe (`InnerSecret`, `Display` on
  `EncodedSecret`, `secure-gate-compat`).

**2. Make a zero-sized `Fixed` unconstructible.** Nothing in the crate needs `Fixed<[u8; 0]>`;
it exists only because `Fixed<T>` is generic and stable Rust cannot state `N > 0` as a bound.
Every constructor funnels through two bodies, `Fixed::new` (generic impl, called by
`From<[u8; N]>` and `Clone`) and `Fixed::<[u8; N]>::new_with` (called by `TryFrom<&[u8]>`,
all decoders, `from_random`, `from_rng`, `Deserialize`), so two post-monomorphization
`const` assertions cover every path. Once the alias macros go, the only zero-size guard left
would be inside `fixed_newtype!`; moving it into `Fixed` makes it cover every spelling. A
generic function still compiles; the error fires at the first concrete zero-sized
instantiation, pointing at the assertion with a note naming the caller. Strictly better than
today's silence. `Dynamic` has no compile-time equivalent and gets none: emptiness of a
`Vec` or `String` is a runtime fact.

**3. Keep the `generic` arm of `dynamic_newtype!`, close design-record §5.4 as decided, and
add the matching `fixed_newtype!(pub Name, generic T)` arm.** Both wrappers are generic over
any `Zeroize` inner type and `RevealSecret` is implemented for all of them; only the
shape-specific extras (`SecretLen`, encoders, `io::Write`, `from_random`, `From<&str>`) are
tied to `String` / `Vec<u8>` / `[u8; N]`. The `generic` arm emits exactly the surface the base
offers for an arbitrary `T`; hand-written that is about forty lines. `dynamic_newtype!` has
it because its inner type is a `:ty` token and trap 6 forced an explicit fallback;
`fixed_newtype!` takes a size literal so the ambiguity never arose and the arm was never
built. The real-world gap is `no_std`: on `thumbv7em-none-eabihf` (which CI cross-builds)
there is no allocator, so `Dynamic` does not exist and `Fixed` is the only wrapper. A secret
there is often not bytes: an ML-KEM secret polynomial `[i16; 256]` (this crate's downstream
is age-pq), Ed25519 scalar limbs `[u64; 4]`, AES-256 expanded round keys `[u32; 60]`. Today
none of those can be newtyped by macro on the one target where `Fixed` is mandatory.

**4. Backport all three to `release/0.8`.** Verified against `origin/release/0.8` (`021f66a`),
not the design record's stale "not a candidate for 0.8" note: the branch is `0.8.0-rc.12`,
single crate at root, and already carries the newtype macros (rc.11), `new_with`, the same
four alias macros, the same alias tests and compile-fail case, and the same `Fixed<[u8; 0]>`
call sites. `src/macros/` differs from `main` only in two file headers and a `rand` bound.
The README calls the line "security patches only", but it is still an rc, it already took the
newtype feature, and leaving the aliases there while removing them on `main` is exactly the
silent re-divergence `docs/audits/pr-182-backport-ledger.md` warns about. Constraints that
override a straight cherry-pick: MSRV 1.70, edition 2021, rustdoc and compile-fail jobs
pinned to 1.70, and a `rand` version that spells the RNG bound `TryRngCore`.

Versions are not bumped on either branch: both bump at release close-out (`dabb14b`,
`da9161f`), so entries go under `## [Unreleased]`. Three commits on `main`'s branch, one per
decision; then a second branch off `release/0.8` with the same three commits cherry-picked
(`-x`) and re-derived where 0.8 differs. Push each branch once at the end. No PRs unless asked.

---

## Workstream A: remove the four alias macros

### A1. Delete

- `src/macros/fixed_alias.rs`, `dynamic_alias.rs`, `fixed_generic_alias.rs`,
  `dynamic_generic_alias.rs`.
- `tests/macros_suite/fixed.rs`, `dynamic.rs`, `fixed_generic.rs`, `dynamic_generic.rs`; drop
  the four `mod` lines from `tests/macros_suite/mod.rs`. Their three `*_zero_size_accepted`
  tests get no replacement (workstream B makes the property false anyway).
- `tests/compile-fail/fixed_alias_zero_size.rs` + `.stderr`; delete
  `fixed_alias_zero_size_compile_fail` at `tests/compile_fail_tests.rs:10-15`.

### A2. `src/macros/mod.rs`

- Drop the four `mod *_alias;` lines.
- Retitle: the module is the nominal newtype macros.
- Replace "# Aliases or newtypes?" with "# Newtype or plain `type`?": a plain Rust `type`
  alias gives a readable name with every wrapper guarantee and stays interchangeable with its
  base; two such aliases of one shape are the same type. A newtype is a distinct type. One
  sentence: the crate used to ship `*_alias!` macros expanding to exactly that `type` line,
  removed in this release (point at the CHANGELOG).
- Table: `type Name = Fixed<[u8; N]>;` (No, Always), `type Name = Dynamic<T>;` (No, `alloc`),
  `fixed_newtype!` (Yes, Always), `dynamic_newtype!` (Yes, `alloc`). Note `generic T` on
  both newtype rows (workstream C).
- Security note: rewrite around workstream B (B4). Keep the FromWrapper/IntoWrapper "pool"
  paragraph; "alias-typed value" → "base-typed value (any plain `type` alias included)".
- Example: `type Aes256Key = Fixed<[u8; 32]>;` on the alias side; newtypes unchanged.

### A3. Newtype macro rustdoc: remove every intra-doc link to a deleted macro (both CIs deny rustdoc warnings)

`src/macros/fixed_newtype.rs`: `:9-13` ("Mirrors `fixed_alias!` syntax" → generates a
`struct` rather than a `type` alias; two same-`N` newtypes are distinct where two `type`
aliases are one type), `:59-60` (drop "exactly as with `fixed_alias!`"), `:110-112`
(rewritten in B4), `:130` ("alias-typed" → "base-typed"), `:156-167` (say "plain `type`
alias" once), `:172-176` See also (drop both alias bullets; add one line pointing at the
module doc for the plain-`type` case).

`src/macros/dynamic_newtype.rs`: same at `:9-11`, `:136`, `:163-173`, `:181-186`.

### A4. `src/lib.rs`

- `:81-88`: replace the `fixed_alias!` doctest with a `fixed_newtype!` one.
- `:106`: `macros/ ← fixed_newtype!, dynamic_newtype!`.
- `:213-215`: `[`fixed_newtype!`]` only, plus a clause that a plain `type` needs nothing.
  `:220`: drop the two dynamic alias links.
- `:498`: comment → "Newtype macros (`dynamic_newtype!` needs `alloc`)".

### A5. `README.md` (live doctests via `ReadmeDoctests`, gated on `full`)

- `:18-21` Quick Start: `use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};`,
  `pub type Password = Dynamic<String>;`, `pub type Aes256Key = Fixed<[u8; 32]>;`. Drop
  `Fixed` from the inner `use` at `:43`.
- `:133-167` → "### Named secret types". Lead with the plain `type` alias and the rc.9 "right
  reach" paragraph reworded from "Aliases are" to "A plain `type` alias is". Code block:
  `/// 32-byte AES-256 key` + `pub type Aes256Key = Fixed<[u8; 32]>;`,
  `#[cfg(feature = "alloc")] pub type Password = Dynamic<String>;`. Newtype half unchanged
  plus one sentence on `generic T` (C). `:167` link list: only the two newtype macros.
- `:169-184` zero-size note: rewritten in B5.
- `:202` "What You Get": a plain `type` alias inherits redacted `Debug` and zeroize-on-drop
  and stays interchangeable with its base; `fixed_newtype!` / `dynamic_newtype!` when
  distinct roles share a shape.

### A6. `SECURITY.md`

- `:248-253` and `:266`: rewritten in B5.

### A7. Tests and benches that keep compiling under `type`

- `tests/compile-fail/newtype_no_from_wrapper.rs:7,9,11`: `use secure_gate::{Dynamic, Fixed,
  dynamic_newtype, fixed_newtype};`, `pub type FileId = Dynamic<String>;`,
  `pub type VaultKey32 = Fixed<[u8; 32]>;`. Line count unchanged; the `.stderr` already
  names `Dynamic<String>` / `Fixed<[u8; 32]>`, so it should stay byte-identical. Verify.
- `tests/compile-fail/newtype_cross_role.rs:3-5` and `newtype_zero_size.rs:1,4`: reword
  "over `fixed_alias!`" / "matching `fixed_alias!`'s guard" **without changing line count**
  (stderr anchors at `:16`, `:11`, `:8`).
- `tests/macros_suite/newtype_conversion.rs:4,6`: `pub type FileId = Dynamic<String>;` (the
  R6 coexistence pin, now against a plain `type`).
- `tests/macros_suite/newtype.rs:5-6` comment; `tests/proptest_suite/ct_eq.rs:6,8-10` three
  `type` lines; `tests/compile_fail_tests.rs` comments at `:157-159`, `:167`, `:185-187`.
- `benches/fixed_vs_raw.rs`: `:7` drop the import, `:10` `pub type RawKey = Fixed<[u8; 32]>;`,
  `:2`, `:87`, `:91`, `:142`, `:156` `fixed_alias` → `type_alias` (criterion baselines are
  untracked, nothing breaks).

### A8. CI

- `.github/workflows/fuzz-miri.yml:55,128`: drop `--skip fixed_alias_zero_size_compile_fail`.

### A9. `CHANGELOG.md`, `## [Unreleased]`, new `### Removed` above `### Testing`

House style: bold lead, long-form reasoning, then **Migration**.

- **BREAKING: the four alias macros are deleted.** What each expanded to. Why: a macro from
  a security crate reads as a guarantee and these guaranteed a name; the README's own
  "type-safe wrappers" wording from 0.5.1 to rc.7 and the downstream reliance `fe93540`
  records; the 34-to-8 collapse; newtypes dominate on every axis at zero cost; the `type`
  line is shorter and unmistakable. The rc.9 "right reach" guidance is unchanged and now
  reads with `type`.
- **Migration** table:
  `fixed_alias!(pub X, N);` → `pub type X = Fixed<[u8; N]>;`
  `fixed_alias!(pub X, N, "doc");` → `/// doc` + the same line
  `dynamic_alias!(pub X, T);` → `pub type X = Dynamic<T>;`
  `fixed_generic_alias!(pub X);` → `pub type X<const N: usize> = Fixed<[u8; N]>;`
  `dynamic_generic_alias!(pub X);` → `pub type X<T> = Dynamic<T>;`
  plus a regex pair for the first two forms. The `N = 0` guard now lives in `Fixed` itself
  (workstream B). Both release lines carry the change; the last tags with the macros are
  `v0.9.0-rc.9` and `v0.8.0-rc.12`.

### A10. `docs/design/nominal_newtypes.md` status header

One amendment paragraph (the header already carries amendments in this form): the alias
macros are removed; `fixed_alias!` / `dynamic_alias!` below describe the earlier crate and
read as `type Name = ...`; R6 now reads "coexist with plain `type` aliases" and
`newtype_conversion.rs` still pins it; Q6's recipe is unchanged in substance.

### A11. Deliberately untouched

`docs/design/secure-gate-requested-newtyping-requirements.md` (the consumer's own words);
`docs/design/recommended_{macro,cloneable,serializable}_improvements.md` and
`docs/plans/base32_encoding.md` (historical); past CHANGELOG entries; `Cargo.toml`.

---

## Workstream B: `Fixed` rejects zero-sized contents at construction

### B1. `src/fixed.rs`: one spelling for both branches

Inline `const { }` blocks need Rust 1.79 and 0.8 is MSRV 1.70, so spell the guard as an
associated `const` on both branches. The hunk then cherry-picks cleanly and the two lines
read identically. Constructor bodies at `:252` and `:353` are byte-identical on `main` and
`release/0.8`.

```rust
impl<T: zeroize::Zeroize> Fixed<T> {
    /// Post-monomorphization guard: a zero-sized `T` has nothing to protect. Fires at the
    /// first concrete construction, never at the declaration. An associated `const` rather
    /// than an inline `const {}` block so the same hunk builds on the 0.8 line's MSRV 1.70.
    const NON_ZERO_SIZED: () = assert!(
        ::core::mem::size_of::<T>() > 0,
        "secure-gate: Fixed<T> cannot hold a zero-sized value; there is nothing to protect"
    );

    pub const fn new(value: T) -> Self {
        let () = Self::NON_ZERO_SIZED;
        Fixed { inner: value }
    }
}

impl<const N: usize> Fixed<[u8; N]> {
    const NON_ZERO_LEN: () = assert!(
        N > 0,
        "secure-gate: Fixed<[u8; 0]> cannot be constructed; there is nothing to protect"
    );

    pub fn new_with<F>(f: F) -> Self where F: FnOnce(&mut [u8; N]) {
        let () = Self::NON_ZERO_LEN;
        // unchanged body
    }
}
```

`T` is `Sized` (inline field). `assert!` with a literal message is const-stable since 1.57.
**Corrected during implementation:** the `()` pattern is NOT exempt from clippy's
`let_unit_value`. Clippy 1.70, this line's MSRV, rejects it, while 1.85 accepts it, and the
alternatives clippy suggests — a bare path statement and `_ =` — are rejected by both. An
explicit `#[allow(clippy::let_unit_value)]` with a comment is the only form clean on both,
and it is what shipped. Struct docs (`:138-227`): add a short "# Zero-size" section: building
a `Fixed` whose value has zero size is a compile error raised at monomorphization, so it fires
wherever a concrete zero-sized instantiation is constructed, generic code included; naming the
type still compiles. `new` docs (`:233-250`): one line pointing there.

### B2. Call sites that instantiate `Fixed<[u8; 0]>` today (identical on both branches)

- `tests/encoding_suite/base32.rs:83-88` `fixed_try_from_base32_zero_size`: rewrite as
  `base32_empty_string_decodes_to_nothing` on the `Vec<u8>` decoder,
  `assert_eq!("".try_from_base32().unwrap(), Vec::<u8>::new())` (`FromBase32Str` is already
  imported at `:6`). `:121` → `assert!("=".try_from_base32().is_err());`. `:138` →
  `assert!("M".try_from_base32().is_err());`. The surrounding comments stay accurate.
- `fuzz/fuzz_targets/encoding.rs:77`: `Fixed::<[u8; 0]>::try_from_hex("")` →
  `Fixed::<[u8; 1]>::try_from_hex("")` (empty input against a nonzero `N` is the error path;
  the no-panic property is what the line exists for).

### B3. New compile-fail case

`tests/compile-fail/fixed_zero_size.rs`: `Fixed::new([0u8; 0])`,
`Fixed::<[u8; 0]>::new_with(|_| {})`, and `fixed_newtype!(pub Z, generic [u8; 0]); Z::new([])`
(workstream C) in `main`. Register as `fixed_zero_size_compile_fail`, `#[cfg(not(miri))]`,
in `tests/compile_fail_tests.rs`. Bless with `TRYBUILD=overwrite` on each branch's pinned
toolchain (1.85 on `main`, 1.70 on 0.8; the two `.stderr` files will differ, as several
already do). If a toolchain reports only the first post-mono error, split into one file per
line. `tests/compile-fail/newtype_zero_size.rs` doc comment: the macro's guard fires at the
declaration; `Fixed` itself fires at construction (line count unchanged).

### B4. Macro docs

- `src/macros/fixed_newtype.rs:59-65, 110-112`: the macro's `[(); N][0]` guard is kept as a
  declaration-site courtesy with a clearer location; `Fixed` rejects the same thing at
  construction, which is what covers a plain `type` alias and the `generic` arm.
- `src/macros/dynamic_newtype.rs:115-117`: "Unlike `Fixed`, there is no compile-time
  zero-size check: a `Dynamic` is pointer-sized whatever it holds".
- `src/macros/mod.rs` security note: `fixed_newtype!` rejects `N = 0` at the declaration and
  `Fixed` rejects zero size at construction; `dynamic_newtype!` has no compile-time
  equivalent, validate lengths that come from configuration in tests.

### B5. README and SECURITY.md

- `README.md:169-184`: replace the three-row table and the "could reject it ... not
  implemented today" paragraph with: a zero-length `Fixed` cannot be built; `Fixed::new` and
  `new_with` carry a `const` assertion, so `Fixed<[u8; 0]>` and any zero-sized inner type are
  a compile error at first construction, through generic code included; `fixed_newtype!(Name,
  0)` additionally fails at the declaration; naming the type without building one still
  compiles; `Dynamic` has no compile-time equivalent, so check lengths that come from
  configuration.
- `SECURITY.md:248-253`: same collapse. `:266`: "`Dynamic<T>` has no size check; empty
  contents are a runtime fact. `Fixed` rejects zero size at construction."

### B6. `CHANGELOG.md`, `## [Unreleased]`, `### Changed`

- **BREAKING: a zero-sized `Fixed` no longer constructs.** The rc.9 entry recorded that the
  guard lived only in `fixed_alias!` and that `Fixed` could carry it as a post-mono `const`
  assertion; it now does, in the two constructor bodies every path funnels through. What
  fires, where, and why naming the type still compiles. **Migration:** nothing, unless
  `Fixed<[u8; 0]>` was built on purpose; decoder tests that used it as an empty-input vehicle
  move to the `Vec<u8>` decoders, as this crate's own did.

---

## Workstream C: `fixed_newtype!(pub Name, generic T)`

### C1. `src/macros/fixed_newtype.rs`

Add two arms, placed **before** the `$size:literal` arms (they match on the literal token
`generic`, so the size arms are untouched; mirrors the proven `dynamic_newtype!` ordering at
`dynamic_newtype.rs:475-483`, bare then `derive:`; doc comes through `$(#[$attr:meta])*` as
it does there):

```rust
($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty) => {
    $crate::fixed_newtype!($(#[$attr])* $vis $name, generic $inner, derive: []);
};
($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty, derive: [$($opt:ident),* $(,)?]) => {
    $crate::__sg_newtype_base!(
        $(#[$attr])* $vis $name($crate::Fixed<$inner>), derive: [$($opt),*]
    );
    impl $name {
        /// Wraps a value in place. `const fn`, like `Fixed::new`.
        #[inline(always)]
        pub const fn new(value: $inner) -> Self { Self($crate::Fixed::new(value)) }
    }
};
```

No `[(); N][0]` guard (there is no `N`); `Fixed::new`'s assertion (B1) covers zero size. No
`SecretLen`, `new_with`, `From`, `TryFrom`, encoders or RNG constructors: none has a meaning
for an arbitrary `T`, matching the `dynamic_newtype!` generic arm exactly. `T: Zeroize` is
enforced by `Fixed<T>`'s bound, reported from the expansion. Add a catch-all last, mirroring
`dynamic_newtype.rs:489-500`: `compile_error!` naming both fixes (a byte-size literal, or
`generic <type>`), so `fixed_newtype!(pub X, [u8; 32])` stops failing with "no rules expected".

Rustdoc: syntax block gains `fixed_newtype!(pub Name, generic T);` and the `derive:` form.
New section "# Inner types other than bytes", mirroring `dynamic_newtype.rs:91-108`: the
`no_std` motivation (no allocator, so no `Dynamic`; secret is a limb or coefficient array),
example `fixed_newtype!(pub Poly, generic [i16; 256]);`, what you get and what you do not,
and that zero size is rejected by the wrapper at construction. Name no version in this doc:
the 0.8 copy of the file carries its own "backported in rc.11" header.

### C2. Tests

- `tests/newtype_nostd.rs`: `fixed_newtype!(pub Poly, generic [i16; 256]);` and a test:
  `Poly::new([0i16; 256]).with_secret(|c| c.len()) == 256`, `size_of::<Poly>() == 512`. No
  `format!` (the file is `no_std` without `alloc`).
- `tests/macros_suite/newtype_surface.rs`: `fixed_newtype!(pub RoundKeys, generic [u32; 60]);`
  beside `Wide`, and a `fixed_generic_arm_surface` test: `new`, `with_secret`,
  `with_secret_mut`, `expose_secret`, `format!("{:?}") == "[REDACTED]"`, `size_of == 240`.
- Zero size through the arm is pinned in B3.

### C3. Docs and records

- `src/macros/mod.rs` table (A2) and `README.md` newtype paragraph (A5): one sentence that
  both macros take `generic T` for an inner type that is not bytes or a string and give the
  shape-independent surface.
- `CHANGELOG.md`, `## [Unreleased]`, `### Added`: `fixed_newtype!(pub Name, generic T)`, the
  `no_std` rationale and the three concrete shapes, what the arm emits, that `Fixed` itself
  rejects zero size.
- `docs/design/nominal_newtypes.md` §5.4 (`:414-419`) and the `:292` heading: **DECIDED: keep.**
  The explicit marker answered the silent-degradation concern; the arm is the only macro path
  for custom inner types, which `Dynamic<T: ?Sized + Zeroize>` supports on purpose; this
  release adds the `Fixed` counterpart for the `no_std` case.

---

## Workstream D: backport to `release/0.8`

### D1. Facts verified against `origin/release/0.8` (fetched; head `021f66a`)

- `0.8.0-rc.12`, MSRV 1.70, edition 2021, `rust-toolchain.toml` pins `1.70`, single crate at
  root with the same layout as `main`.
- Carries the newtype macros, `new_with`, the four alias macros, the alias tests, the
  `fixed_alias_zero_size` compile-fail case, and the same `Fixed<[u8; 0]>` sites
  (`tests/encoding_suite/base32.rs:85,121,138`, `fuzz/fuzz_targets/encoding.rs:77`).
- `src/macros/` differs from `main` only in: the two file headers ("Ships in 0.9.0; backported
  to the 0.8 line in 0.8.0-rc.11 ... It describes `main`"), `TryRngCore` for `TryRng` in the
  `from_rng` bound (rand version), and pre-existing `â€”` mojibake in `dynamic_newtype.rs`
  (observed, not in scope; leave it).
- Drift in the doc files: `README.md` (~144 lines; the macros section sits at `:142-178` and
  still carries the pre-rc.9 zero-size wording at `:174-176`, so `e0da564`'s "right reach"
  paragraph never reached 0.8), `src/lib.rs` (alias lines at `:74,76,98,205,212,490`),
  `SECURITY.md` (`:251-253`, `:266`, same as `main`), `docs/design/nominal_newtypes.md` (header
  57 lines shorter), `src/fixed.rs` (29 lines elsewhere; the two constructor bodies are
  identical).
- CI: `ci-0.8.yml` skips compile-fail cases by the `compile_fail` substring, runs them in a
  dedicated job on 1.70 (`TRYBUILD=overwrite cargo +1.70 test compile_fail` is the documented
  bless command), runs the MSRV job as `cargo +1.70 test -p secure-gate --locked
  --all-features`, and runs rustdoc with `-D warnings` on 1.70. `fuzz-miri-0.8.yml:54` carries
  `--skip fixed_alias_zero_size_compile_fail`.
- `CHANGELOG.md` has no `## [Unreleased]` yet (head is `## [0.8.0-rc.12] - 2026-09-09`). Its
  house style for mirrored work: "Mirrors the same change on `main`, re-derived against this
  branch rather than copied". Its rc.12 `### Changed` already carries "SECURITY.md gained the
  zero-length-secret entry from `main`", which B now supersedes.
- Rust 1.70 is not installed locally; the worktree's `rust-toolchain.toml` makes rustup fetch
  it on the first `cargo` call (1.85 was fetched the same way in this session).

### D2. Mechanics

1. `git worktree add /home/user/secure-gate-0.8 -b claude/alias-macros-necessity-0.8 origin/release/0.8`.
   Branch name follows the line's convention (`claude/error-payload-freedom-0.8`,
   `claude/remove-compat-0.8`).
2. `git cherry-pick -x <A> <B> <C>` in order. Expected clean: `src/macros/*.rs` bodies,
   `tests/macros_suite/*`, `tests/proptest_suite/ct_eq.rs`, `tests/compile-fail/*.rs`,
   `tests/compile_fail_tests.rs`, `benches/fixed_vs_raw.rs`, `fuzz/fuzz_targets/encoding.rs`,
   `tests/encoding_suite/base32.rs` (three small hunks), `src/fixed.rs` (identical bodies,
   identical guard spelling by design), `tests/newtype_nostd.rs`. Expected conflicts:
   `README.md`, `src/lib.rs`, `SECURITY.md`, `docs/design/nominal_newtypes.md`, `CHANGELOG.md`,
   and the workflow hunk (`fuzz-miri.yml` does not exist on 0.8).
3. Conflict rule, from the ledger: write the end state against 0.8's own wording, never paste
   `main`'s. Before touching each file, `git show origin/release/0.8:<path> | grep` the anchor.
   - `README.md`: rewrite `:142-178` as the new "Named secret types" section from A5 + B5
     (this is also the first time the "right reach" paragraph lands on 0.8; say so in the
     CHANGELOG entry); Quick Start at `:32`.
   - `src/lib.rs`: the A4 edits at `:74-80`, `:98`, `:205-212`, `:490`.
   - `SECURITY.md`: `:251-253`, `:266` per B5.
   - `docs/design/nominal_newtypes.md`: the A10 amendment and the C3 §5.4 closure, placed
     where 0.8's shorter header ends.
   - `.github/workflows/fuzz-miri-0.8.yml:54`: drop `--skip fixed_alias_zero_size_compile_fail`.
     No other CI change.
   - `CHANGELOG.md`: new `## [Unreleased]` with `### Removed`, `### Changed`, `### Added`
     mirroring `main`'s three entries, each closing with the re-derivation sentence, and the
     zero-size entry noting it supersedes rc.12's SECURITY.md paragraph.
4. `cargo +1.70 fmt --all` after resolving (2021 import ordering differs from 2024 style).
5. Bless `tests/compile-fail/fixed_zero_size.stderr` on 1.70 with the documented command;
   confirm `git diff --stat` shows only that `.stderr` changed among snapshots.
6. Run the 0.8 verification block; `git push -u origin claude/alias-macros-necessity-0.8`.

---

## Verification

`main` branch (toolchain 1.85 via `rust-toolchain.toml`):

```sh
cargo fmt --all --check
cargo clippy --features full --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features       # dangling intra-doc links fail here
cargo test --features full                                            # integration + README doctests
cargo test --all-features                                             # std-gated newtype forwarding
cargo test --no-default-features                                      # no-alloc path: fixed_newtype! + the generic arm
cargo test --no-default-features --test newtype_nostd                 # Poly over [i16; 256]
cargo test --no-default-features --features encoding-bech32           # the CI row that expands fixed_newtype! without alloc
TRYBUILD=overwrite cargo test --features full --test compile_fail_tests   # bless fixed_zero_size on 1.85, then:
cargo test --features full --test compile_fail_tests                  # clean run; git diff shows only the new .stderr
cargo bench --all-features --bench fixed_vs_raw --no-run
cargo check --manifest-path fuzz/Cargo.toml                           # may need nightly; else rely on CI fuzz-quick
grep -rn "alias!" src tests benches README.md SECURITY.md .github     # expect zero hits
grep -rn "u8; 0\]" src tests fuzz                                     # expect only tests/compile-fail/fixed_zero_size.rs
```

`release/0.8` worktree (toolchain 1.70 via its `rust-toolchain.toml`; `+1.70` is explicit):

```sh
cd /home/user/secure-gate-0.8
cargo +1.70 fmt --all --check
cargo +1.70 clippy --features full --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo +1.70 doc --no-deps --all-features
cargo +1.70 test -p secure-gate --locked --all-features -- --skip compile_fail --skip serializable_secret_misuse   # the MSRV job's exact line
cargo +1.70 test --features full
cargo +1.70 test --no-default-features
cargo +1.70 test --no-default-features --test newtype_nostd
TRYBUILD=overwrite cargo +1.70 test --features full --test compile_fail_tests ; cargo +1.70 test --features full --test compile_fail_tests
grep -rn "alias!" src tests benches README.md SECURITY.md .github     # expect zero hits
grep -rn "u8; 0\]" src tests fuzz                                     # expect only tests/compile-fail/fixed_zero_size.rs
```

## Out of scope

- Any runtime emptiness check on `Dynamic`. Emptiness of a `Vec` or `String` is a runtime
  fact and an empty `Dynamic<String>` is a legitimate value to hold before validation.
- `SecretLen` on the `generic` arms, even when `T` is an array. The macro cannot see the shape;
  parity with the `dynamic_newtype!` generic arm is the rule.
- The `â€”` mojibake in 0.8's `dynamic_newtype.rs` and the `TryRngCore` bound difference: both
  pre-exist and neither is touched by these hunks.
- Opening pull requests for either branch, unless asked.
- Bumping 0.8's MSRV. Considered (1.79 would allow inline `const {}` blocks) and declined for
  this change: the associated-`const` spelling costs nothing, the low MSRV is the line's
  reason to exist, and the branch's real toolchain pains (lockfile v4 readability, the rustdoc
  1.70 ICE, the `atty` advisories, `core::error::Error` at 1.81) justify a bump on their own
  terms, to 1.81 or later, as a separate decision with its own CHANGELOG entry.
