# Nominal Newtypes over `Fixed` and `Dynamic` (`fixed_newtype!` / `dynamic_newtype!`)

> **Status: unmerged spike. Targets 0.10 — deliberately NOT part of 0.9.0.**
> The code on this branch compiles and its tests pass, but one design decision
> (§5.1) is unresolved and is a security-posture call, not an implementation
> detail. Do not merge until §5.1 is settled.
>
> Tracking issue: #155. Branch: `claude/fixed-dynamic-newtype-hl7e19`.
> Not a candidate for `release/0.8` — that branch is security patches only.
>
> **Superseded in part by `docs/composability_restructure.md`** (same branch,
> 0.9.0 candidate): §3.3 is now implemented (wrapper encoders are trait
> impls) and trap 7 is fixed (`RevealSecret` now covers custom inner types,
> which previously had no access impl at all). The spike macros in
> `src/macros/` have been updated to match.
>
> **§5.1 remains the blocker** — an earlier revision of this note claimed the
> restructure resolved it. It does not. A generated newtype being local means a
> user *can* hand-write `impl Clone for EncKey` (verified), but that impl must
> still route through `with_secret`, because `Fixed<[u8; 32]>: Clone` requires
> `[u8; 32]: CloneableSecret` and that is permanently unimplementable
> downstream (verified E0277). The "second door" is therefore **narrowed, not
> closed**: what changed is that hand-writing the impl is now clearly viable
> and is the user's own explicit, greppable decision, which makes option (c)
> below — drop `Clone`/`Serialize` from `derive:` entirely — materially more
> attractive than it was. The decision itself is still open.
>
> The restructure did **not** make these macros unnecessary, and an earlier
> draft of this note overstated that. Measured: `src/macros/` went from 427 to
> **522 lines** (encoder forwarding became trait impls), and a hand-rolled
> newtype at parity with `fixed_newtype!(pub EncKey, 32)` still costs **40
> lines** per secret role. Encoders cannot be inherited via a blanket impl
> keyed on `Inner: AsRef<[u8]>`, because `String: AsRef<[u8]>` holds and such
> a blanket would give `Dynamic<String>` hex encoding — the exclusion pinned
> by `tests/compile-fail/dynamic_string_no_hex.rs`. §5.3 is therefore
> **narrowed and made mechanical** (bounded by the trait set) rather than
> dissolved. What remains open: §5.1 (above), the macro-rules-vs-proc-macro
> question (§5.2), and finishing the macro polish (§6).

## Summary

`fixed_alias!` and `dynamic_alias!` generate plain `type` aliases. Two aliases
over the same underlying type are the **same nominal type** and freely
assignable to each other, so the compiler cannot distinguish an encryption key
from a MAC key (both `Fixed<[u8; 32]>`), or an API key from a webhook secret
(both `Dynamic<String>`). `src/macros/mod.rs` and `README.md` both acknowledge
this and tell the reader to "wrap the alias in a `struct` newtype yourself" —
which leaves them with a bare struct: no `RevealSecret`, no redacted `Debug`,
no `Zeroize` forwarding, roughly ten impls per secret type.

This spike closes that gap with two macros that mirror the existing alias
syntax and generate `struct`s instead of aliases:

```rust
fixed_alias!(pub Aes256Key, 32);      // existing — structural
fixed_newtype!(pub EncKey, 32);       // this spike — nominal

dynamic_alias!(pub Password, String); // existing
dynamic_newtype!(pub ApiKey, String); // this spike
```

The bug class targeted is **key-role confusion between same-shaped secrets**:
passing a MAC key where an encryption key belongs, a webhook secret where an
API key belongs, or a cross-tenant key into the wrong tenant's path. Today all
of these compile silently. This is the one class of secret-handling defect the
current design cannot see.

Everything asserted in this document was verified against `rustc` 1.85.1 on
this branch. Error codes cited are actual observed output, not predictions.

## 1. What is implemented

| File | Contents |
|---|---|
| `src/macros/newtype_common.rs` | `__sg_newtype_base!` (internal) + cfg relay macros |
| `src/macros/fixed_newtype.rs` | `fixed_newtype!` front end |
| `src/macros/dynamic_newtype.rs` | `dynamic_newtype!` front end + `__sg_dynamic_ctor!` |
| `src/lib.rs` | `__private` re-export module (`#[doc(hidden)]`, semver-exempt) |
| `tests/newtype_spike.rs` | 5 tests, `--features full` |
| `tests/newtype_spike_nostd.rs` | 1 test, `--no-default-features` and `--features encoding-hex` |

Separation is at the **front end only**. Both macros delegate to one shared
`__sg_newtype_base!` that emits the struct, the accessors, and the whole trait
surface; the per-family macros add only what needs concrete type knowledge.
There is no duplicated trait forwarding.

`__sg_newtype_base!` emits: the `#[repr(transparent)]` struct, `from_wrapper` /
`as_wrapper` / `as_wrapper_mut` / `into_wrapper`, `Debug` (always
`[REDACTED]`), `From<Wrapper>`, `RevealSecret`, `RevealSecretMut`, `Zeroize`,
`ZeroizeOnDrop`, and the opt-in `derive:` impls.

`fixed_newtype!` adds: the `N = 0` guard, `const fn new`, `new_with`,
`From<[u8; N]>`, `TryFrom<&[u8]>`, `from_random`, `try_from_hex`, `to_hex`,
`to_hex_upper`, `to_hex_zeroizing`, `to_hex_upper_zeroizing`, `try_to_bech32`,
`try_from_bech32`.

`dynamic_newtype!` adds, per arm: `new` for every inner type; `From<&str>` and
`new_with` on the `String` arm; `From<&[u8]>`, `new_with`, `from_random(len)`,
`try_from_hex`, `to_hex`, `to_hex_zeroizing`, `io::Write` and `as_reader` on
the `Vec<u8>` arm.

Zeroization needs no forwarding: the newtype holds the wrapper, and the
wrapper's own `Drop` runs. `#[repr(transparent)]` keeps
`size_of::<EncKey>() == 32`.

## 2. Why the split front end (and not one macro)

The unified form `secure_newtype!(pub EncKey(Fixed<[u8; 32]>))` was built first
and is **strictly worse**, because a macro holding an opaque `$wrapper:ty`
cannot forward inherent methods with correct `Self` return types.

Splitting is therefore not cosmetic. With `N` known at expansion:

- Constructors return the newtype. `EncKey::from_random()` yields an `EncKey`,
  not a `Fixed<[u8; 32]>` needing `from_wrapper`.
- `impl From<[u8; N]>` is concrete, so `let k: EncKey = [0u8; 32].into()`
  works. Under the unified macro the only expressible form was a blanket
  `impl<U> From<U> for K where Fixed<[u8; 32]>: From<U>`, which is **E0119**
  against the base macro's own `From<Wrapper>`. Verified.
- The `N = 0` guard reuses `fixed_alias!`'s exact `[(); $size][0]` trick and
  produces the identical "index out of bounds" diagnostic, so the guard story
  matches the alias story instead of being bespoke.
- `dynamic_newtype!` gives correct **per-inner-type** APIs: the `Vec<u8>` arm
  has `to_hex` / `io::Write` / `as_reader`; the `String` arm correctly has
  **no** `to_hex` (verified E0599). One macro could only have offered the
  lowest common denominator.

The call-site syntax also lines up with the macro family already shipped — a
`fixed_alias!` user can guess `fixed_newtype!`.

## 3. Rejected alternatives

### 3.1 `Deref` to the wrapper — rejected

Tested with `impl Deref for Aes256Key { type Target = Fixed<[u8; 32]> }`.

- **Covers only half the surface.** `&self` methods resolve (`key.to_hex()`
  works with no forwarding). Associated functions do **not** — `Aes256Key::new`,
  `::from_random`, `::try_from_hex` all give **E0599**, because `Deref` applies
  to method receivers, never to path resolution. Even if they resolved they
  would return `Fixed<[u8; 32]>`, the wrong type.
- **Destroys the premise.** `fn takes_raw(w: &Fixed<[u8; 32]>)` accepts both
  `&EncKey` and `&MacKey` — verified, both compile. Deref coercion reinstates
  exactly the structural equivalence the newtype exists to remove, leaving
  nominal separation intact only for by-value arguments. A guarantee that holds
  only sometimes is worse than none.
- **Contradicts stated posture.** `README.md`'s first security bullet is "No
  `Deref` while held", enforced by `tests/compile-fail/fixed_no_deref.rs` and
  `dynamic_no_deref.rs`. The secret itself would stay gated (the target is
  `Fixed`, which has no `Deref` of its own), so this is a posture and
  greppability cost rather than a leak — but on this crate that still counts.

### 3.2 Phantom tag parameter — rejected, but note the deadline

`Fixed<T, Tag = ()>` carrying `PhantomData<fn() -> Tag>` would give nominal
separation with **zero** forwarding: every existing inherent method and trait
impl would cover tagged types automatically, all feature gates included. It is
the only design where the full API comes for free.

Rejected because type-parameter defaults do not apply in expression position:
`let k = Fixed::new([0u8; 32]);` with no annotation stops inferring (**E0282**),
breaking user code and many of the crate's own doctests. Pinning constructors
to the `Tag = ()` impl fixes inference but then tagged types need their own
constructor, which downstream crates cannot write as an inherent impl (orphan
rules).

**This is the only time-sensitive decision in this document.** The tag design
changes the flagship types' signatures, so it can only ever land pre-1.0. The
newtype macros are purely additive and can land in any release. If tagging is
ever seriously wanted, that call must be made before 1.0; otherwise this
section is the record of why it was not taken.

### 3.3 Trait-ifying the inherent encoders — viable, not yet taken

Inherent methods cannot be delegated generically; traits can (that is why
`RevealSecret` forwarding is one type-agnostic arm). Moving the encoder surface
onto traits would let the base macro forward it in one place.

**Verified: there is no coherence obstacle.** `impl<const N: usize> ToHex for
Fixed<[u8; N]>` compiles cleanly alongside the existing blanket
`impl<T: AsRef<[u8]> + ?Sized> ToHex for T`, because `Fixed` is local and
deliberately does not implement `AsRef<[u8]>`, so `rustc` can rule out overlap
locally. The initial assumption that this would be **E0119** was wrong.

Not taken in this spike because the split front end already covers the same
methods concretely. Worth revisiting if the forwarding list grows: it would
shrink the per-family macros and benefit `Dynamic`'s generic arm, which today
gets no encoders at all.

## 4. Verified traps

Each was hit during development; the fix (where applicable) is in the code.

1. **Where-clauses on concrete impls are not opt-outs.** `impl Clone for P
   where Dynamic<String>: Clone` is **E0277** at the impl site — bounds on
   impls for concrete types are checked eagerly (rust#48214). Conditional
   forwarding is therefore impossible; hence the explicit `derive:` opt-in
   list. This produced 8 errors on the first build.
2. **`#[cfg(feature = "…")]` inside an exported macro reads the *caller's*
   features.** Silently wrong, not an error. Fixed with cfg relay macros
   (`__sg_if_hex!`, `__sg_if_rand!`, …) defined in this crate, where the cfg is
   meaningful. Verified by expanding from a downstream crate whose feature
   names differ from this crate's.
3. **`::alloc::…` paths do not resolve downstream.** Every expansion failed
   with **E0433** in an ordinary `std` test crate, which has no `extern crate
   alloc`. Fixed by routing through `$crate::__private::{String, Vec, Box}`.
   The alias macros never hit this because the user writes the inner type.
4. **`Dynamic::new_with` is ambiguous.** Two inherent impls define it
   (`Dynamic<Vec<u8>>` and `Dynamic<String>`), so unqualified calls are
   **E0034**. All generated calls are fully qualified as
   `<Dynamic<String>>::new_with(…)`. Easy to reintroduce when adding forwarders.
5. **A user-added `Drop` on the newtype breaks `into_inner`.** **E0509**,
   "cannot move out of type which implements `Drop`". No `Drop` is needed —
   the wrapper's own runs — but the error is opaque. Needs a doc warning.
6. **Literal-token arms are fragile.** `dynamic_newtype!(pub P, MyStr)` where
   `type MyStr = String` silently falls through to the generic arm; `P::new_with`
   then does not exist (**E0599** at the use site, far from the cause). Same for
   a spelled-out `std::string::String`. `macro_rules!` matches tokens, not
   resolved types. **There is no `macro_rules!` fix** — only documentation
   ("write `String` and `Vec<u8>` exactly"), or a proc macro (§5.2).
7. **The macro's floor is `RevealSecret`'s floor.** `RevealSecret` is
   implemented only for `Fixed<[T; N]>`, `Dynamic<String>` and
   `Dynamic<Vec<T>>`. A custom inner type — including the `SessionKey` pattern
   in `traits/cloneable_secret.rs` that the marker-trait docs recommend — has
   no `RevealSecret` impl, so it cannot be newtyped: `Fixed<Sess>: RevealSecret
   is not satisfied`, reported from inside the expansion. Needs a doc note, or
   an opt-out flag for the reveal impls.
8. **Laundering compiles.** `MacKey::from_wrapper(enc.into_wrapper())` is legal.
   Nominal separation guards against mistakes, not intent, and closing this
   would also close legitimate access to the wrapper API. Both hatch names are
   greppable. Document it; do not try to prevent it.

## 5. Open questions — resolve before merging

### 5.1 BLOCKER: expose-based `Clone` / `Serialize` derives

`derive: [Clone]` cannot forward the wrapper's `Clone`, because that requires
`[u8; 32]: CloneableSecret`, which the orphan rule makes **permanently**
unimplementable downstream — deliberately so, per
`traits/cloneable_secret.rs`. A forwarding derive would therefore error on
every realistic type.

The spike instead clones and serializes **through `with_secret`**, making the
generated newtype itself the audit point. That is arguably exactly the role the
marker-trait docs assign to a local newtype, and it is written in the user's own
code and greppable.

But it is also a **second door**: `dynamic_newtype!(pub P, String, derive:
[Serialize])` opts a `Dynamic<String>` into serialization with no
`SerializableSecret` impl anywhere. Whether that is acceptable is a
security-posture decision for the crate owner, and it deserves the same
standard of reasoning the `Display`-removal entry in `CHANGELOG.md` received.

Options: (a) keep as-is and document loudly; (b) require the marker trait
anyway, which makes the derives unusable for stdlib inner types; (c) drop
`Clone`/`Serialize` from `derive:` entirely and make users hand-write them;
(d) gate them behind a distinct, louder opt-in token.

**Recommendation: (a), (c), or (d).** Not (b) — it ships a feature that cannot
be used. Decide explicitly; do not let the spike's choice become the default by
inertia.

**What the composability restructure changed here (and what it did not).** It
does **not** resolve this. Verified on the restructured branch:

- A user can hand-write `impl Clone for EncKey` on a macro-generated newtype —
  it compiles and works, because the newtype is local to their crate.
- That impl must still route through `with_secret`, because
  `Fixed<[u8; 32]>: Clone` requires `[u8; 32]: CloneableSecret`, which remains
  permanently unimplementable downstream (**E0277**).

So the bypass is unchanged in mechanism. What changed is *who owns it*: an
explicit hand-written impl in the user's own code is a visible, greppable
decision, whereas a `derive: [Clone]` token spells the same bypass in one word
inside a macro expansion. That materially strengthens option **(c)** — drop
`Clone`/`Serialize` from the `derive:` list and let users write them by hand
when they mean it.

### 5.2 `macro_rules!` or proc macro?

Trap 6 has no `macro_rules!` fix. A proc macro would resolve inner types
properly and remove the literal-arm fragility, but adds `syn` + `quote` to a
crate whose selling points include a minimal dependency graph,
`forbid(unsafe_code)`, and `no_std` cleanliness. Decide the mechanism **before**
users depend on the behaviour — switching later is disruptive even if
technically non-breaking.

### 5.3 Scope of the forwarded surface

The spike forwards a representative subset. Full parity additionally needs
base64, bech32m, the `_zeroizing` bech32 variants, `from_rng`, and
`deserialize_with_limit`. Alternatively adopt §3.3 and forward traits instead.
Decide before writing the remaining ~25 forwarders by hand.

### 5.4 Should the generic `Dynamic` arm exist at all?

It yields a newtype with no constructors beyond `new` and no encoders. It may
be better to reject non-`String`/`Vec<u8>` inner types outright with a clear
message than to hand back a type that silently lacks most of the API — which is
also what makes trap 6 hurt.

## 6. Remaining work to ship

1. Resolve §5.1, then §5.2 and §5.3.
2. Complete the forwarded surface per §5.3.
3. Rustdoc in house style: syntax block, all visibility forms, custom-doc arm,
   `# Implementation Notes`, `# Security`, `# See also` cross-links to the alias
   macros — matching `fixed_alias!`. Also correct the prose that these macros
   make obsolete: `src/macros/mod.rs` (module doc, and the macro table) and
   `README.md` both currently end with "wrap the alias in a `struct` newtype
   yourself", and `secure-gate-core/README.md` carries the same claim.
4. Doc note for traps 5, 6, 7, 8.
5. `trybuild` compile-fail cases: cross-role assignment (E0308), `N = 0`,
   user-added `Drop` (E0509), `to_hex` absent on the `String` arm.
6. Move the spike tests into `tests/macros_suite/`.
7. Confirm zero-overhead against `benches/fixed_vs_raw.rs`; consider extending
   `tests/asm_dse_check.rs` to a newtype.
8. `CHANGELOG.md` entry under `Unreleased`.
9. Feature-matrix CI: the relays mean expansions differ per feature
   combination, so the newtype tests need to run across the same 20
   combinations the crate already tests.

## 7. Verification

Current spike state, all passing on this branch:

```sh
cargo test  --features full --test newtype_spike           # 5 passed
cargo test  --no-default-features --test newtype_spike_nostd  # 1 passed
cargo test  --no-default-features --features encoding-hex --test newtype_spike_nostd
cargo test  --features full                                # full suite, 334 passed
cargo fmt   --all --check
cargo clippy --features full --all-targets
```
