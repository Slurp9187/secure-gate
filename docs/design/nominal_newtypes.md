# Nominal Newtypes over `Fixed` and `Dynamic` (`fixed_newtype!` / `dynamic_newtype!`)

> **Status: ships in 0.9.0 — in the next release candidate, alongside the
> composability restructure (`docs/design/composability_restructure.md`, #156).**
> §5.1 is decided and implemented (option (c): `Clone`/`Serialize` dropped
> from `derive:`, callers write them by hand), §5.2 is decided (stay with
> `macro_rules!`; trap 6 fixed by the explicit `generic` marker), §6 polish is
> complete, and the downstream cross-check (§8) is done. Shipping in the same
> release as #156 matters: #156 breaks any hand-rolled `RevealSecret` impl
> (`len` moved to `SecretLen`), and these macros are the landing spot for
> exactly those consumers.
>
> Tracking issue: #155. Branch: `claude/fixed-dynamic-newtype-hl7e19`.
> Not a candidate for `release/0.8` — that branch is security patches only.
>
> **Superseded in part by `docs/design/composability_restructure.md`** (same branch,
> 0.9.0 candidate): §3.3 is now implemented (wrapper encoders are trait
> impls) and trap 7 is fixed (`RevealSecret` now covers custom inner types,
> which previously had no access impl at all). The spike macros in
> `src/macros/` have been updated to match.
>
> **§5.1 was decided in favour of option (c)** and is implemented. Note that
> the restructure did **not** resolve it on its own — an interim revision of
> this note claimed so and was retracted. A generated newtype being local
> means a user *can* hand-write `impl Clone for EncKey` (verified), but that
> impl must still route through `with_secret`, because `Fixed<[u8; 32]>:
> Clone` requires `[u8; 32]: CloneableSecret`, permanently unimplementable
> downstream (verified E0277). The restructure only changed *ownership* of
> the bypass, which is what made (c) the right call: the macro no longer
> spells it in one word, and a caller who wants it writes it visibly in their
> own code.
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
> dissolved. What remains open: finishing the macro polish (§6).
>
> **Amended again: the alias macros are gone, and this document outlived two of
> its own claims.** `fixed_alias!`, `dynamic_alias!`, `fixed_generic_alias!` and
> `dynamic_generic_alias!` were removed after the newtype macros had shipped long
> enough to show that nothing reached for an alias macro where a plain `type`
> line would not do. Read every reference to them below as describing the earlier
> crate: `fixed_alias!(pub K, 32)` is now `pub type K = Fixed<[u8; 32]>;` and
> `dynamic_alias!(pub P, String)` is now `pub type P = Dynamic<String>;`. The
> arguments are unaffected, because they were always about `type` aliases being
> structural — the macro was only ever a wrapper around one. R6 (§8) now reads
> "coexist with plain `type` aliases", which `tests/macros_suite/newtype_conversion.rs`
> still pins, and Q6's migration recipe is unchanged in substance.
>
> Two claims above are now false and are left in place as a record rather than
> silently corrected. Line 14's "Not a candidate for `release/0.8` — that branch
> is security patches only" was overtaken by events: the newtype macros were
> backported to the 0.8 line in 0.8.0-rc.11, and the alias removal is backported
> too. And §2's framing of the zero-size guard as something only the macros carry
> (the `[(); $size][0]` trick, there credited to `fixed_alias!`) no longer holds:
> `Fixed::new` and `Fixed::new_with` now assert a non-zero size themselves, so the
> guard covers a hand-written `type` as well. `fixed_newtype!` keeps its own
> declaration-site guard because that one fires earlier, at the macro call. That
> assertion is a post-monomorphization error and therefore invisible to
> `cargo check`, which is a real limit worth knowing before relying on it.

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

`__sg_newtype_base!` emits: the `#[repr(transparent)]` struct, `Debug` (always
`[REDACTED]`), `RevealSecret`, `RevealSecretMut`, `Zeroize`, `ZeroizeOnDrop`,
and the opt-in `derive:` impls (`ConstantTimeEq`, `Deserialize`,
`FromWrapper`, `IntoWrapper`, `WrapperAccess` — `Clone`/`Serialize` are
rejected, see §5.1). It emits **no** `From<Wrapper>` and **no** `Deref` (§8,
R2/R3): base-wrapper access is opt-in per newtype and split by direction —
`FromWrapper` adds `from_wrapper` (inbound), `IntoWrapper` adds `as_wrapper` /
`as_wrapper_mut` / `into_wrapper` (outbound), `WrapperAccess` is both.

`fixed_newtype!` adds: the `N = 0` guard, `const fn new`, `new_with`,
`From<[u8; N]>`, `TryFrom<&[u8]>`, `from_random`, `try_from_hex`, `to_hex`,
`to_hex_upper`, `to_hex_zeroizing`, `to_hex_upper_zeroizing`, `try_to_bech32`,
`try_from_bech32`.

`dynamic_newtype!` arms: `String` and `Vec<u8>` are matched as **literal
tokens** and get the full API for their shape; any other inner type requires an
explicit `generic` marker and gets the reduced surface (no `SecretLen`, no
encoders); anything else is a compile error naming both options (trap 6).

It adds, per arm: `new` for every inner type; `From<&str>` and
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

**Amendment (rc.9): that holds for *concrete* impls only, and the distinction is
why per-type forwarding exists at all.** A second *blanket* impl keyed on the
wrapper trait — the one shape that would let any newtype inherit the encoder
surface without forwarding — is genuinely rejected:

```text
error[E0119]: conflicting implementations of trait `ToHex`
   impl<T: AsRef<[u8]> + EncodableBytes + ?Sized> ToHex for T   // first
   impl<T: RevealSecret> ToHex for T                            // conflicting
```

`rustc` cannot prove the two bounds disjoint — there is no negative reasoning —
so it refuses regardless of whether any type actually satisfies both. Reproduced
standalone rather than inferred.

This is also why implementing `RevealSecret` on a hand-written newtype buys none
of the encoders: `to_hex` resolves through the byte-shaped blanket, and a wrapper
is deliberately not byte-shaped. Confirmed by compiling one — the error is
`method `to_hex` not found ... doesn't satisfy `ApiKey: AsRef<[u8]>``.

The two findings compose: concrete per-wrapper impls are legal (§ above), a
blanket over the wrapper trait is not, and the note at the head of this document
gives the semantic reason a blanket would be wrong even if it were legal —
`String: AsRef<[u8]>` holds, so it would hand `Dynamic<String>` hex encoding,
which `tests/compile-fail/dynamic_string_no_hex.rs` exists to forbid.

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
6. **Literal-token arms are fragile — FIXED via the `generic` marker.**
   `dynamic_newtype!(pub P, MyStr)` where `type MyStr = String` used to fall
   through to the generic arm silently; `P::new_with` then did not exist
   (**E0599** at the use site, far from the cause). Same for a spelled-out
   `std::string::String`. Macros match tokens, not resolved types — and this is
   true of proc macros too, which run before type resolution (§5.2).

   The fix is to remove the silent path, not to see through the alias: the
   generic arm now requires an explicit `generic` marker
   (`dynamic_newtype!(pub P, generic MyStr)`), and anything unrecognised hits a
   catch-all that names both options. Pinned by
   `tests/compile-fail/dynamic_newtype_alias_rejected.rs`.

   **Arm-ordering hazard found while implementing this.** `macro_rules!` does
   not backtrack once a `:ty` fragment has been parsed. A single
   `$inner:ty, $doc:literal` doc arm placed first will consume the type, fail
   to find the comma, and hard-error with "unexpected end of macro invocation"
   — never reaching the literal arms below. Doc-string forms are therefore
   written once per shape, matched by literal tokens, *before* any arm opening
   with a `:ty` fragment; and the catch-all uses `$($rest:tt)+` rather than
   `$inner:ty` so it can never itself hard-error on a malformed tail.
7. **The macro's floor is `RevealSecret`'s floor.** `RevealSecret` is
   implemented only for `Fixed<[T; N]>`, `Dynamic<String>` and
   `Dynamic<Vec<T>>`. A custom inner type — including the `SessionKey` pattern
   in `traits/cloneable_secret.rs` that the marker-trait docs recommend — has
   no `RevealSecret` impl, so it cannot be newtyped: `Fixed<Sess>: RevealSecret
   is not satisfied`, reported from inside the expansion. Needs a doc note, or
   an opt-out flag for the reveal impls.
8. **Laundering requires opt-in on both sides.** Originally
   `MacKey::from_wrapper(enc.into_wrapper())` compiled unconditionally, and the
   base macro also generated `From<Wrapper>`, so an alias-typed value could
   become a newtype through a one-line `.into()`. Both are gone (§8, R2): no
   `From<Wrapper>` is generated, and the named base-access methods exist only
   with `derive: [FromWrapper]` / `[IntoWrapper]` (`WrapperAccess` = both), so
   relabelling needs `FromWrapper` on the *receiving* type. By default the only path between roles is a
   `with_secret` round trip — explicit, and visible in the audit sweep. Pinned
   by `tests/compile-fail/newtype_no_from_wrapper.rs`.

## 5. Open questions (all decided: §5.1, §5.2 and §5.4 below; §5.3 narrowed and completed per §6)

### 5.1 DECIDED (option (c)): `Clone` / `Serialize` are not generated

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

**Decided: option (c).** `Clone` and `Serialize` are dropped from the `derive:`
list. Asking for either is now a compile error carrying the reasoning and the
alternative:

```text
secure_newtype: `derive: [Clone]` is not supported. Cloning a secret cannot be
forwarded (the wrapper's `Clone` needs `CloneableSecret` on the inner type,
which downstream crates cannot implement), so a generated impl would route
around the opt-in marker system. Write `impl Clone for YourType` by hand if you
mean it — the newtype is local to your crate, so the decision stays visible in
your code.
```

Rationale for (c) over (a)/(d): the bypass cannot be removed — a hand-written
impl must route through `with_secret` too — so the only question is **who owns
the decision and how visible it is**. A `derive: [Clone]` token buries it in a
macro expansion; a hand-written impl puts it in the caller's own code, where
review and `grep` find it. (b) was rejected outright: requiring the marker
would ship a feature unusable for every stdlib inner type.

Implemented as: `compile_error!` arms in `__sg_newtype_opt!`, pinned by
`tests/compile-fail/newtype_derive_clone_rejected.rs` and
`newtype_derive_serialize_rejected.rs`; an unknown `derive:` token also gets a
named error listing the supported set. The hand-written `Clone` path is shown
as a compiling doctest on `fixed_newtype!`. `ConstantTimeEq` and `Deserialize`
remain supported — neither bypasses anything: they delegate to wrapper impls
that are already correctly gated (`Deserialize` *constructs* a protected
secret rather than exposing one).

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

### 5.2 DECIDED: stay with `macro_rules!`

**Correction first.** Earlier revisions of this document claimed a proc macro
"would resolve inner types properly" and so fix trap 6. That is **wrong**.
Proc macros run during macro expansion, *before* name resolution and type
checking; a proc macro receives `MyStr` as an opaque identifier token, exactly
as `macro_rules!` does, and stable Rust exposes no API for looking through a
type alias at that stage. Both macro kinds are equally blind here. Trap 6 is
not a `macro_rules!` limitation — it is a property of macros.

**What actually fixes trap 6** (implemented): make the fallback explicit. The
generic arm now requires a `generic` marker, so an unrecognised bare type no
longer falls through and silently loses the shaped API — it is a compile error
that names the fix. See trap 6 for the current behaviour.

**What a proc macro would still buy, honestly:** better diagnostics (precise
spans and wording), and easier maintenance if the generation logic grows past
what arms carry comfortably. The diagnostics point is real — see the arm-order
note in trap 6 for how easily `macro_rules!` produces "unexpected end of macro
invocation" when arms are arranged wrong.

**Decision: stay with `macro_rules!`.** The correctness hazard (silent
degradation) is fixed without new dependencies; what remains is message
quality, which does not justify adding `syn` + `quote` to a crate whose
selling points include a minimal dependency graph, `forbid(unsafe_code)`, and
`no_std` cleanliness. Revisit only if the generation logic outgrows arms.

**Amendment (rc.9): half of that dependency argument no longer holds.**
`syn`, `quote` and `proc-macro2` are already in the published graph whenever the
`serde` feature is on, pulled in by `serde` → `serde_derive` — and `full`
enables `serde`. Measured on 0.9.0-rc.9 with `cargo tree -p secure-gate
--features=full --edges normal`. So for the configuration most users select,
a derive macro would add a crate to the graph, not a compiler-plugin toolchain.

The objection survives only for `--no-default-features` builds, which are
exactly the `no_std` ones the argument was written to protect — so the decision
stands, but on narrower ground than "adding `syn`". The real reasons to stay put
are now: the macros work and are covered by `tests/macros_suite/`, rewriting
tested generation before 1.0 is churn against a real risk of behaviour drift,
and the maintenance cost is bounded and rare (an encoder signature change
touches the forwarding sites once — the `Case` parameter in rc.9 hit sixteen
across `fixed.rs`, `dynamic.rs` and both newtype macros). If that number grows,
that is the signal, not the dependency count.

### 5.3 Scope of the forwarded surface

The spike forwards a representative subset. Full parity additionally needs
base64, bech32m, the `_zeroizing` bech32 variants, `from_rng`, and
`deserialize_with_limit`. Alternatively adopt §3.3 and forward traits instead.
Decide before writing the remaining ~25 forwarders by hand.

### 5.4 DECIDED: keep the generic arm, and give `Fixed` one too

The worry was that the arm hands back a type "that silently lacks most of the
API". The `generic` marker that fixed trap 6 removed the silent part, which was
the whole of the objection: an unrecognised inner type is now a `compile_error!`
naming both options, so nothing degrades quietly, and writing the word `generic`
is how a caller states that the reduced surface is what they meant.

What is left is not a degraded newtype but the correct one. `SecretLen` and the
encoders are absent because neither has a meaning for an arbitrary `T` — a length
in `u32` elements is not the byte length callers expect, and hex over a
`Vec<u32>` has no defined byte order. The arm is also the only macro path to any
inner type other than `String` and `Vec<u8>`, which `Dynamic<T: ?Sized + Zeroize>`
supports deliberately and which the trap-7 fix (`RevealSecret` covering custom
inner types) exists to enable. Hand-rolling parity costs the ~40 lines measured
in the status header above.

Rejecting those inner types outright, the alternative this section floated, would
undo the trap-7 fix for exactly the consumers it was made for.

`fixed_newtype!` has gained the matching `generic T` arm. It had none only because
it takes a size literal, so the token ambiguity that forced the marker never arose
there — not because `Fixed` is less generic. The gap mattered most on `no_std`,
where there is no allocator and therefore no `Dynamic` at all, so `Fixed` is the
only wrapper and the secret is often not bytes: an ML-KEM secret polynomial
`[i16; 256]`, Ed25519 scalar limbs `[u64; 4]`, an AES-256 expanded key schedule
`[u32; 60]`. Pinned by `tests/newtype_nostd.rs` and
`tests/macros_suite/newtype_surface.rs`.

## 6. Polish — COMPLETE

All items done; feature-complete. Ships in 0.9.0 (see the status header).

1. ✅ §5.1 decided (option (c)); §5.2 decided (stay with `macro_rules!`);
   §5.3 narrowed and completed.
2. ✅ Forwarded surface completed: hex, base64, bech32, bech32m (encode + the
   `_zeroizing` variants + decode constructors, incl. the `_unchecked` forms),
   `from_random`, `from_rng`. `derive:` is now passed through by both front
   ends — previously it was reachable only via the base macro.
3. ✅ Rustdoc in house style on both macros: syntax block, all visibility
   forms, custom-doc and `derive:` arms, `# Implementation Notes`,
   `# Security`, `# See also`. Obsolete prose corrected in
   `src/macros/mod.rs` (module doc rewritten around the alias-vs-newtype
   choice, macro table extended with a "Nominal?" column) and
   `secure-gate-core/README.md` (macro section rewritten, security bullet
   updated). The workspace `README.md` never carried the claim.
4. ✅ Doc notes for traps 5 (`Drop`/E0509), 6 (`generic` marker), 7 (fixed by
   #156), 8 (laundering via the named escape hatches).
5. ✅ `trybuild` cases — 13 total, including cross-role assignment (E0308),
   `N = 0`, user-added `Drop` (E0509), `to_hex` absent on the `String` arm,
   the alias rejection, and both rejected `derive:` options.
6. ✅ Tests moved into `tests/macros_suite/` (`newtype.rs`,
   `newtype_surface.rs`). The no-std test stays a separate binary because it
   needs a crate-level `no_std` attribute; renamed `tests/newtype_nostd.rs`.
7. ✅ Zero-overhead confirmed, and more strongly than planned:
   `src/bin/asm_check.rs` gained a `make_and_drop_newtype` symbol, and LLVM
   emits `.set make_and_drop_newtype, make_and_drop_fixed` — identical-code
   folding, i.e. the newtype compiles to *byte-identical* machine code, not
   merely equivalent code. `tests/asm_dse_check.rs` follows the alias
   directive and asserts the zero-stores against the fold target.

   Whether the fold happens is the toolchain's call, and zeroize 1.9 changed it:
   its `asm!` barrier pushes the zeroization out of line into
   `core::ptr::drop_glue::<Fixed<[u8; 32]>>`, and the two wrappers now survive as
   separate symbols with identical bodies calling that same glue. The transparency
   result stands either way, and the test accepts both shapes.
8. ✅ `CHANGELOG.md` entry under `Unreleased`.
9. ✅ Feature-matrix coverage: the newtype tests live inside the `integration`
   binary (`macros_suite`), so the existing 20-combination CI matrix already
   runs them — no workflow change needed. Verified locally across the 17 core
   combinations the matrix uses; all green.

**Pre-existing failure, found here and fixed in the rc.8 bump (#157):** under
`--no-default-features --features=std`, `tests/compile-fail/dynamic_no_deref.rs`
mismatched its expected stderr. Confirmed identical on the pre-restructure
baseline, so it was unrelated to this work. Root cause was diagnostic, not
semantic: with `std` enabled `Dynamic<Vec<u8>>` implements `io::Write`, and rustc
appended a ``help: there is a method `by_ref` with a similar name`` note to the
E0599 for `secret.as_ref()`. (CI's "std explicit" job was not red — it skips the
compile-fail cases by name; only the local matrix hit it.) The probe now goes
through the trait, `AsRef::<Vec<u8>>::as_ref(&secret)`, which yields E0277 with
no similar-name lookup and is byte-identical across `alloc`, `std`, and `full`.

**CI skip lists, found while preparing the PR:** the stable test jobs skipped
compile-fail cases by an enumerated list of six names, so the eleven cases added
on this branch would have run on stable — eight mismatch on stable 1.94 through
diagnostic drift alone. The jobs now skip by the `*_compile_fail` name suffix.

## 8. Downstream cross-check: `encrypted-file-vault` requirements

`docs/secure-gate-requested-newtyping-requirements.md` (a consumer with 34
aliases collapsing to 8 real types, and an IPC-boundary design that alias
synonymy defeated) states requirements R1–R7 and questions Q1–Q7. Status on
this branch, verified by tests unless noted:

| Req | Requirement | Status |
|---|---|---|
| R1 | Distinct identity for both `Dynamic` and `Fixed` | ✅ `fixed_newtype!` / `dynamic_newtype!`; `newtype_cross_role.rs` |
| R2 | Controlled conversion; no blanket `From`/unwrap-rewrap | ✅ **Was violated** — the base macro generated `From<Wrapper>`. Removed; base access is now opt-in per newtype **and per direction** (`FromWrapper` / `IntoWrapper`; `WrapperAccess` = both); default path is a `with_secret` round trip. `newtype_no_from_wrapper.rs` |
| R3 | No `Deref` to the base | ✅ never generated; now pinned by `newtype_no_deref.rs` |
| R4 | Preserve zeroize, `[REDACTED]` `Debug`, no `Display`, 3-tier access | ✅ struct holds the wrapper (its `Drop` runs); no `Display` is generated; `RevealSecret`/`RevealSecretMut` forwarded; `asm_dse_check` proves byte-identical codegen |
| R5 | Opt-in `Serialize` per newtype, not per base | ✅ by §5.1 (c): hand-write `impl Serialize for PublicId` routing through `with_secret`. Siblings and the base gain nothing — `newtype_sibling_not_serializable.rs` |
| R6 | Coexist with plain `type` aliases in one file | ✅ `newtype_conversion.rs` mixes a `type` alias with four newtypes; R2 is what makes the mix safe. (Stated as "alias macros" when written; those are gone, and a `type` alias is what they expanded to, so the requirement is unchanged) |
| R7 | Match the hand-written shape: `new(impl Into<String>)`, private field, `RevealSecret`, `[REDACTED]` | ✅ **Was mismatched** — `new` took `Into<Box<String>>`, so `new("literal")` failed. Shaped arms now take `impl Into<String>` / `impl Into<Vec<u8>>`. Note the hand-written `RevealSecret` impl in the requirements includes `len()`, which moved to `SecretLen` in #156 — adopting the macro absorbs that |

Answers to Q1–Q7:

1. **Names and syntax.** `fixed_newtype!(vis Name, N [, "doc"] [, derive: [..]])`
   and `dynamic_newtype!(vis Name, String | Vec<u8> | generic T [, "doc"]
   [, derive: [..]])` — the alias macros' `(vis, name, inner)` / `(vis, name,
   size)` shape, plus an optional `derive:` list.
2. **Conversion.** None by default. No `From`/`Into` between a newtype and its
   base, nor between newtypes. `derive: [WrapperAccess]` adds the four named,
   greppable methods. Raw-material constructors remain (`From<[u8; N]>`,
   `From<&str>`, `From<&[u8]>`, `TryFrom<&[u8]>`) — they build from
   non-secret input, not from another secret type.
3. **`Deref`.** No. Pinned.
4. **Per-newtype `Serialize`.** Yes — hand-written, ~6 lines, through
   `with_secret`. The base can never implement it (`String:
   SerializableSecret` is orphan-blocked), so a sibling cannot inherit it.
5. **`Fixed` coverage.** Yes, first-class; the key-confusion case is the
   headline example.
6. **Migration from `pub type X = SecureString`.** Replace the alias with
   `dynamic_newtype!(pub X, String)`. Call sites using `X::new(..)`,
   `with_secret`, `expose_secret`, `into_inner`, or `"…".into()` compile
   unchanged. Call sites that assigned a base value to `X`, or passed `&X`
   where `&SecureString` was expected, stop compiling — those are exactly the
   substitutions the newtype exists to catch. `len()` calls need
   `use secure_gate::SecretLen;` (from #156, independent of newtypes).
7. **Generic contexts.** `fn f<T: RevealSecret<Inner = String>>` accepts
   `PublicId`, `FileId`, and the base, and that is intended: nominal identity
   is a property of the type; trait bounds are structural. To exclude
   siblings, bound on the concrete type, or define a local marker trait and
   implement it for the newtypes you mean.

### Direction matters

The two directions of base access carry different risk, which is why the
opt-in is split rather than a single switch. Both risks come from the same
fact: in a mixed tree the base type is not raw material, it is a **pool**.
Every plain alias sharing `Dynamic<String>` *is* `Dynamic<String>`, so a
directional token connects one role to every alias in the pool at once.

- **Inbound** (`FromWrapper` → `from_wrapper(base) -> Self`) lets anything in
  the pool become this role. `PublicId::from_wrapper(file_id)` compiles with no
  opt-in on the source side at all — the source never opts in, because the
  source is just the base type. A type whose purpose is to guard a boundary
  must never take `FromWrapper`; doing so reopens exactly the substitution the
  newtype exists to refuse, one named call instead of one `.into()`.
- **Outbound** (`IntoWrapper` → `as_wrapper`, `as_wrapper_mut`, `into_wrapper`)
  lets this role become anything in the pool. It cannot forge a label — the
  result is the base type, and reaching another role still needs that role's
  `FromWrapper` — but it can drop a label into a pool where the label never
  existed. `mp.into_wrapper()` on a `MasterPassword` yields a `Dynamic<String>`
  assignable to `Status`, and `Status` is the sort of thing that gets formatted
  into a log. So `IntoWrapper` is safe only when the role is **no more
  sensitive than the least-sensitive plain alias sharing its base**; on a secret
  role it is an explicit, greppable downgrade, not a neutral operation. (For
  `PublicId` the same move is benign: public → internal is over-restriction,
  not leakage.) It remains far better than `From`, because it is a call site an
  audit can find; it is not "safe".
- `WrapperAccess` is both, for internal roles at the same level as their pool
  in both directions. Do not combine it with a directional token — the methods
  would be defined twice (E0592, verified).

**The default is sufficient more often than it looks.** The downstream
consumer's headline boundary type, `PublicId`, needs zero tokens: a census of
every operation on one found 17 `PublicId::new`, 3 `.expose_secret()`, and 5
struct-field shorthands — all available by default — and nothing that hands a
`PublicId` to base-typed code. The most restrictive setting is also the
sufficient one, which is the right place for the default to sit.

**This matters most during a partial migration**, which is where any real
consumer lives for a long time (that consumer newtyped 1 of 34 aliases,
deliberately). While most aliases stay plain, the base type is a universal
donor and both rules above are load-bearing. Once every alias is a newtype the
pool holds only anonymous base values from constructors, and the exposure
collapses to "base-typed code" — the regime the rules were written for is the
mixed one, not the endgame.

The two directional tokens cross a different wall from `into_inner`. A newtype
has two walls, and every method sits in one cell:

| Wall | Going in | Going out |
|---|---|---|
| Contents (the wrapper's protection) | `new`, `From<raw>` | `with_secret`, `expose_secret`, `into_inner` |
| Role (the nominal label) | `from_wrapper` | `as_wrapper`, `as_wrapper_mut`, `into_wrapper` |

`into_inner` leaves the protection: the `InnerSecret` it returns derefs, so the
contents are in the caller's hands (tier 3, audited). `into_wrapper` only
removes the label: the result is still a `Dynamic`, still unreadable without
`with_secret`, and nothing is revealed. The role row exists so that dropping a
label never forces opening the contents — without it, handing a value to
base-typed code costs an `into_inner` plus a rebuild: a reveal the job never
needed, an extra copy to zeroize, and a false positive in the reveal audit.

Pinned by `tests/compile-fail/newtype_directional_access.rs`: a type with only
`IntoWrapper` has no `from_wrapper`, and one with only `FromWrapper` has no
`into_wrapper`.

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
