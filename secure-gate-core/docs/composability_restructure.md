# Composability Restructure: `SecretLen` Split + Trait-Based Encoders

> **Status: shipped.** Merged to `main` in PR #159 (`f2a8f1c`) and released in
> **0.9.0-rc.8**; layered on the `fixed_newtype!`/`dynamic_newtype!` work
> (#155, `docs/nominal_newtypes.md`), which ships in the same release.
> Breaking relative to earlier 0.9.0 release candidates; no stable release had
> shipped, so it was the cheapest possible moment.
>
> **`release/0.8` backport: done.** Landed via PR #160 (`a029bb7`) and released
> as **0.8.0-rc.11**, so both lines expose the same trait shape. Nothing here
> uses post-1.70 language features, and the backport was mechanical — with one
> deliberate omission recorded in that branch's changelog: the
> `dynamic_string_no_hex` compile-fail fixture is not carried over, so the
> `Dynamic<String>`-has-no-hex claim is unpinned on 0.8.
>
> Tracking issue #156 is closed. This document is kept as the design record.

## The diagnosis

The crate conflated two axes: **storage** (stack `Fixed` vs heap `Dynamic`)
and **capability** (reveal, measure, encode, compare, clone, serialize).
Capabilities were bolted onto storage as inherent methods and shape-restricted
trait impls, which produced three concrete defects:

1. **The crate's own recommended pattern was broken.** `RevealSecret` was
   implemented only for `Fixed<[T; N]>`, `Dynamic<String>`, and
   `Dynamic<Vec<T>>` — because it carried `len()`, and a generic `T` has no
   meaningful length. The narrow impls dragged `with_secret`/`expose_secret`
   down with them, so the local-inner-newtype pattern that
   `cloneable_secret.rs` and `serializable_secret.rs` *instruct users to
   write* produced a secret that could be cloned, serialized, and zeroized —
   but **never read**. `Fixed<SessionKey>` had no access API at all.
2. **Inherent encoder methods could not be abstracted over.** ~20 methods
   duplicated per wrapper family, unreachable from generic code
   (`fn f<S: ?>(s: &S)` had no bound to name), and unforwardable by newtypes
   without copying every signature.
3. **Nominal newtypes were expensive to write.** The #155 spike needed 427
   lines, much of it transcribing ~47 inherent signatures per wrapper family.
   Note the scope of what this restructure fixes: it makes that forwarding
   *uniform and mechanical* (all trait impls, identical in shape across
   families), not unnecessary. See "Effect on the #155 newtype spike" for
   measured before/after.

## The fix — two mechanical moves

### Move 1: `SecretLen` split, impls widened

```rust
pub trait RevealSecret {          // access — now for EVERY inner type
    type Inner: ?Sized;
    fn with_secret<F, R>(&self, f: F) -> R where F: FnOnce(&Self::Inner) -> R;
    fn expose_secret(&self) -> &Self::Inner;
    fn into_inner(self) -> InnerSecret<Self::Inner> where /* unchanged */;
}

pub trait SecretLen: RevealSecret { // metadata — only where meaningful
    fn len(&self) -> usize;
    fn byte_len(&self) -> usize { self.len() }
    fn is_empty(&self) -> bool { self.len() == 0 }
}
```

Impl matrix after the change:

| Impl | Before | After |
|---|---|---|
| `RevealSecret for Fixed<T>` | only `[T; N]` | **any** `T: Zeroize` |
| `RevealSecret for Dynamic<T>` | only `String`, `Vec<T>` | **any** `T: ?Sized + Zeroize` (one impl) |
| `RevealSecretMut` | same narrow shapes | any `T`, both wrappers |
| `SecretLen` | (didn't exist) | `Fixed<[T; N]>`, `Dynamic<String>`, `Dynamic<Vec<T>>` |

`into_inner` keeps its method-level `Sized + SentinelValue + Zeroize` bound, so
the widening adds no new obligations. `ConstantTimeEq`, `Clone`, and
`Serialize` on the wrappers were already generic over `T` with marker bounds —
the widened `RevealSecret` simply lets them reach custom inner types now.

`Fixed<SessionKey>` is fully usable as of this change: reveal, mutate,
opt-in clone, opt-in serialize, and (given an inner `ConstantTimeEq` impl)
constant-time compare. Pinned by `tests/composability.rs`. `SecretLen` staying
narrow is pinned by `tests/compile-fail/custom_inner_no_len.rs`.

### Move 2: encoders become trait impls on the wrappers

The inherent encode methods on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>`
(`to_hex`, `to_hex_upper`, both `_zeroizing` variants, `to_base64url` +
`_zeroizing`, `try_to_bech32`/`try_to_bech32m` + `_zeroizing` — 10 per family)
are **replaced** by impls of the existing per-format traits:

```rust
impl<const N: usize> ToHex for Fixed<[u8; N]> { /* delegates via with_secret */ }
impl ToHex for Dynamic<Vec<u8>> { /* likewise */ }
// … ToBase64Url, ToBech32, ToBech32m same pattern
```

- **No coherence conflict** with the existing blanket
  `impl<T: AsRef<[u8]> + ?Sized> ToHex for T`: the wrappers are local and
  deliberately do not implement `AsRef<[u8]>`, so the compiler rules out
  overlap. (Verified before implementation — `docs/nominal_newtypes.md` §3.3.)
- **Call syntax is unchanged** — `key.to_hex()` still works — but the trait
  must be in scope: `use secure_gate::ToHex;`.
- **One trait means one bound.** `fn fingerprint<S: ToHex>(s: &S)` now accepts
  `Fixed`, `Dynamic`, and any forwarding newtype. Inherent methods could never
  do this.
- **Decode constructors stay inherent** (`try_from_hex`, `try_from_base64url`,
  `try_from_bech32(±m)(±unchecked)`) — construction needs `Self`, which a
  capability trait cannot provide without much heavier machinery.
- `Dynamic<String>` still has **no** hex encoding. The compile-fail fixture
  was strengthened: it now imports `ToHex` and proves the impl genuinely does
  not exist, rather than merely that an import was missing.

### Move 3 (resolved as smaller than proposed): markers stay on inner types

The earlier sketch suggested moving `CloneableSecret`/`SerializableSecret`
onto wrapper types. Orphan-rule analysis kills that for the core wrappers:
downstream `impl CloneableSecret for Fixed<[u8; 32]>` is E0117 (both trait and
type foreign) — exactly the problem it was meant to solve. The only local
things a downstream crate controls are **local inner types** and **local
newtypes**. So:

- For core wrappers, the inner-type marker mechanism is unchanged — it is the
  only orphan-compatible design, and Move 1 is what makes it *worth using*
  (the pattern now yields a readable secret).
- For local newtypes (the #155 macros), the newtype itself is local, so a user
  *can* hand-write `Clone`/`Serialize` on it directly. This **narrows but does
  not resolve** #155 §5.1: such an impl must still route through `with_secret`
  (`Fixed<[u8; 32]>: Clone` requires `[u8; 32]: CloneableSecret`, permanently
  unimplementable downstream — verified E0277), so the bypass mechanism is
  unchanged. What changes is ownership: a hand-written impl is the user's
  visible, greppable decision, whereas a `derive: [Clone]` token spells the
  same bypass in one word inside a macro expansion. **§5.1 was subsequently
  decided in favour of option (c)** — `Clone`/`Serialize` dropped from
  `derive:`, callers write them by hand — precisely because ownership, not
  mechanism, was the part that could be improved.

## Effect on the #155 newtype spike (updated in the same change)

- The base macro forwards `RevealSecret`/`RevealSecretMut` only;
  `__sg_newtype_len!` forwards `SecretLen` from the shaped front ends — the
  generic `dynamic_newtype!` arm correctly emits no `len`.
- Encoder forwarding became **trait impls** (`impl ToHex for $name` etc., UFCS
  delegation) instead of generated inherent methods — the macro-generated
  newtypes now satisfy the same bounds as the wrappers.
- Trap 7 of `docs/nominal_newtypes.md` (custom inner types cannot be newtyped)
  is fixed by Move 1 — previously they had no `RevealSecret` impl at all.
  §3.3 of that document is now implemented. §5.1 is **decided** (option (c),
  see Move 3 above), §5.2 is **decided** (stay with `macro_rules!`), §6 polish
  is complete, and the downstream cross-check (§8 there) is done. The macros
  ship in 0.9.0 alongside this restructure — deliberately, since this
  restructure breaks any hand-rolled `RevealSecret` impl (`len` moved to
  `SecretLen`) and the macros are the landing spot for those consumers.

### What this did *not* do: shrink the macros

An earlier draft of this document claimed the forwarding surface was "largely
dissolved". Measured, that is wrong, and the correction matters for planning:

| | Before restructure | After |
|---|---|---|
| `src/macros/` total | 427 lines | **522 lines** |
| Hand-rolled newtype at parity with `fixed_newtype!(pub EncKey, 32)` | — | **40 lines** |

The macros grew slightly, because encoder forwarding became trait impls with
UFCS delegation rather than generated inherent methods. A hand-rolled newtype
still needs, per secret role: the struct, `#[repr(transparent)]`, constructors,
`From`, a redacted `Debug` (deriving it prints `EncKey([REDACTED])` — a real
trap), `RevealSecret` ×3, `RevealSecretMut` ×2, `SecretLen` ×2, `ToHex` ×4,
`Zeroize`, and `ZeroizeOnDrop`. The `Dynamic<Vec<u8>>` case adds `io::Write`
and `as_reader` on top.

**Why encoders cannot be inherited by newtypes.** The obvious shortcut — a
blanket `impl<S: RevealSecret> ToHex for S where S::Inner: AsRef<[u8]>` — is
wrong here, because `String: AsRef<[u8]>` holds. That blanket would give
`Dynamic<String>` hex encoding, defeating the deliberate exclusion pinned by
`tests/compile-fail/dynamic_string_no_hex.rs`. Hence the concrete per-wrapper
impls, and hence explicit forwarding by newtypes.

So the restructure changed the *nature* of the per-type cost (uniform trait
forwarding instead of ~47 transcribed inherent signatures) rather than its
size. §5.3 (scope of the forwarded surface) is **narrowed and made
mechanical**, not dissolved — the list is now bounded by the trait set instead
of open-ended, which is what makes the macros tractable to finish.

## Migration (for anyone tracking pre-release 0.9 RCs)

1. `len()` / `byte_len()` / `is_empty()` on a wrapper → add
   `use secure_gate::SecretLen;`.
2. `key.to_hex()` and friends on a wrapper → add the format trait import
   (`ToHex`, `ToBase64Url`, `ToBech32`, `ToBech32m`).
3. Nothing else changes: no call-site rewrites, no behavior changes, no
   feature-gate changes. Measured on this repo's own suite: every migration
   edit was an import line.

## Verification

All on this branch, `rustc` 1.85.1:

```sh
cargo test --features full            # 341 tests incl. doctests, 0 failed
cargo test --no-default-features      # incl. spike no-std tests
cargo check across feature combos     # no-default, encoding-hex (±alloc), encoding, std+serde+ct-eq
cargo clippy --features full --all-targets   # clean
cargo fmt --all --check               # clean
cargo doc  --features full --no-deps  # unresolved-link count identical to baseline (17)
```

Zero-overhead expectation is unchanged (`#[inline]` delegation through
`with_secret`, same as the removed inherent methods); confirm with
`benches/fixed_vs_raw.rs` and `tests/asm_dse_check.rs` in CI as usual.
