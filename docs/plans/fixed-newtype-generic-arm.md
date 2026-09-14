# Plan: tighten `fixed_newtype!`'s `generic` arm

| | |
|---|---|
| **Status** | **Implemented** on `docs/fixed-newtype-generic-arm` (workstreams A and B). C is not in this change. Tracking [#215](https://github.com/Slurp9187/secure-gate/issues/215) |
| **Written against** | `main` at `e504fd1` (`0.9.0-rc.10` unreleased) |
| **Tracking issue** | [#215](https://github.com/Slurp9187/secure-gate/issues/215) |
| **Branch** | `docs/fixed-newtype-generic-arm` |
| **Breaking** | Workstream A is a compile-error for a previously-accepted spelling. Pre-release, so allowed. B and C are additive |
| **MSRV** | Unchanged (1.85). B must stay as an associated method, not an inline `const {}` block, if it is ever backported to 0.8 (MSRV 1.70) |
| **Question that started it** | The `generic` marker is the niche escape hatch for non-byte `Fixed<T>`. What should it actually do, and what should it refuse? |

Three workstreams, in order. A is the only item the audit left as a code fix. B and C are follow-ups from the same discussion; they are not required to close A.

## Context

`fixed_newtype!` has two front ends:

```rust
fixed_newtype!(pub EncKey, 32);                  // shaped: Fixed<[u8; 32]>, full API
fixed_newtype!(pub Poly, generic [i16; 256]);    // generic: Fixed<T>, reduced API
```

The marker exists because macros match tokens, not types. `generic $inner:ty` is one opaque blob, so the expansion withholds `SecretLen`, `new_with`, `From` / `TryFrom`, encoders and RNG rather than guessing. That is correct for a custom struct. It is the wrong trade for two token-visible cases:

1. **`generic [u8; N]` is strictly dominated** by the size-literal arm. It compiles today and silently drops `new_with`, `len()`, `From`, the encoders and the RNG constructors. `dynamic_newtype!` already `compile_error!`s the analogous spellings (`generic Vec<u8>`, `generic String`) at `src/macros/dynamic_newtype.rs:246-264`, with `tests/compile-fail/dynamic_newtype_generic_shaped_rejected.rs`. `fixed_newtype!` has no equivalent. `FixedStorage` does not catch this: `[u8; 32]` is a safe inner type.

2. **`new_with` is meaningful for arbitrary `T`** and is omitted only because `Fixed::new_with` exists solely on `impl<const N: usize> Fixed<[u8; N]>` (`src/fixed.rs:441`). The generic newtype arm therefore has no in-place constructor; `new` takes the secret by value and may leave a copy on the caller's frame. The rustdoc at `src/macros/fixed_newtype.rs:133-141` already says this costs you something.

A third, optional split: `generic [$t:ty; $n:literal]` is still tokens. `[i16; 256]` is the reason the marker exists (no_std ML-KEM polynomial, Ed25519 limbs, AES round keys). It should not have to pretend it is an opaque struct.

## Workstream A — reject `generic [u8; N]` (audit follow-up)

This is the one code change the audit produced. Do it first; it does not depend on B or C.

### A1. Reject arms

Place them **before** the catch-all `generic $inner:ty` arm, matching `dynamic_newtype!`'s shaped-generic rejects. All four tails the generic arm accepts must be pinned, or a later arm-order slip leaves the doc-string / `derive:` forms on the reduced arm:

- `generic [u8; $n:literal]`
- `generic [u8; $n:literal], $doc:literal`
- `generic [u8; $n:literal], derive: [$($opt:ident),*]`
- `generic [u8; $n:literal], $doc:literal, derive: [$($opt:ident),*]`

`compile_error!` wording should name the fix: write `$n`, not `generic [u8; $n]`. The size-literal arm is the full API; this spelling is the same payload with strictly less of it. Do **not** special-case `$n = 0`.

### A2. Move the zero-size trybuild off `[u8; 0]`

`tests/compile-fail/fixed_zero_size.rs:24` uses `generic [u8; 0]` on purpose: `fixed_newtype!(pub Z, 0)` dies at the declaration-site `[(); N][0]` check and never reaches `Fixed::new`'s post-monomorphization guard. After A1 that line is a domination error instead.

Change it to `generic [i16; 0]` (or another non-`u8` ZST array). Regenerate `tests/compile-fail/fixed_zero_size.stderr` on the pinned toolchain (`TRYBUILD=overwrite cargo +1.85 test compile_fail`). Confirm the companion `tests/compile-pass/fixed_nonzero_size.rs` still flips trybuild into `cargo build` mode.

### A3. Tests

New compile-fail, modelled on `dynamic_newtype_generic_shaped_rejected.rs`: all four tails, plus a positive control that `generic [i16; 256]` and `generic [u8; 32]`-by-size-literal still compile. Wire it in `tests/compile_fail_tests.rs`.

### A4. Docs

One paragraph on `fixed_newtype!` rustdoc (the `generic` section) and a matching sentence in `src/macros/mod.rs`. Point at the `dynamic_newtype!` reject as the precedent. No SECURITY.md change — this is domination, not a leak.

CHANGELOG under the open `0.9.0-rc.10` heading, `### Changed`, **BREAKING**. Migration is delete the word `generic` and write the size literal.

---

## Workstream B — `Fixed<T>::new_with`, then forward it

Additive. Do not mix into A's PR unless A is already landed and the diff stays small.

### B1. Inherent `new_with` on `Fixed<T>`

Today only `[u8; N]` can construct in place, by zero-filling the wrapper's own field and handing `&mut [u8; N]` to the closure. A generic version is possible without `unsafe`, using bounds the newtype arm already requires:

```rust
impl<T: zeroize::Zeroize + crate::FixedStorage + crate::SentinelValue> Fixed<T> {
    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce(&mut T),
    {
        let () = Self::NON_ZERO_SIZED;
        let mut this = Self { inner: T::sentinel_value() };
        f(&mut this.inner);
        this
    }
}
```

The sentinel is inert (zeros / `Default`). The closure writes the secret into the wrapper's slot. That is the residue story `Fixed::<[u8; N]>::new_with` already documents. `#![forbid(unsafe_code)]` is untouched; `MaybeUninit` is not needed.

Overlap with the existing `[u8; N]` method: `[u8; N]: SentinelValue` (zero array) and `FixedStorage`, so a generic impl would collide (E0592) with `impl<const N: usize> Fixed<[u8; N]> { fn new_with }`. Resolve by **deleting the byte-array inherent** and letting it use the generic one, *or* by putting the generic method under a different name. Prefer one `new_with`: the byte-array body is `inner: [0u8; N]` which *is* `SentinelValue` for `[u8; N]`. Keep the `NON_ZERO_LEN` assertion if the generic `NON_ZERO_SIZED` does not already cover `[u8; 0]` (it does — `size_of::<[u8; 0]>() == 0`). Verify `new_with` still rejects `[u8; 0]` in `tests/compile-fail/fixed_zero_size.rs`.

### B2. Forward from the generic newtype arm

In `src/macros/fixed_newtype.rs`, the `generic $inner:ty` arm currently emits only `new`. Add:

```rust
pub fn new_with<F>(f: F) -> Self
where
    F: ::core::ops::FnOnce(&mut $inner),
{
    Self($crate::Fixed::new_with(f))
}
```

Same shape as the size-literal arm at `:315`. Update the rustdoc that currently says the generic arm has no `new_with` (`fixed_newtype.rs:133-141`, `dynamic_newtype.rs:132-137` if we do not also do Dynamic — we do not, in this workstream).

### B3. Tests

- Runtime: `fixed_newtype!(pub Poly, generic [i16; 256]); Poly::new_with(|p| p.fill(7));` asserts contents, and that `new_with` is what the size-literal arm already tests for residue intent (stack-trace tests if they cover `new` vs `new_with`).
- Compile-fail still rejects `generic Vec<u8>` via `FixedStorage` — `new_with` must not re-open that; the bound on `Fixed::new_with` is the same allow-list.

### B4. Docs

Rewrite the "absent because it is not generated" paragraph to: the constructor exists on `Fixed<T>` and the generic arm forwards it. CHANGELOG `### Added`. Not breaking.

---

## Workstream C — optional array split (do not start with A)

`generic [$t:ty; $n:literal]` is token-visible. The no_std case this arm exists for is exactly that shape. A dedicated arm can emit:

- declaration-site `N = 0` (`const _: () = { let _ = [(); $n][0]; };`), so `generic [i16; 0]` fails under `cargo check` the way `fixed_newtype!(Name, 0)` already does
- `SecretLen` (`len` = `N` elements, `byte_len` = `N * size_of::<$t>()`), which `Fixed<[T; N]>` already implements
- `new` / `new_with` (B, if landed)

Leave true opaques (`struct Poly([i16; 256])`, a custom field) on the reduced remainder. Do **not** add encoders or RNG: hex over `[i16]` has no byte order.

A1 already rejects `generic [u8; $n]`, so this arm is only non-`u8` arrays. Order: A1 rejects, then `generic [$t; $n]`, then opaque `generic $inner:ty`.

Skip C if A+B are enough and nobody is asking for `len()` on `Poly`. It is a convenience, not a safety fix.

---

## Non-goals

- Encoders / RNG on opaque `T`.
- `From<Fixed<T>>` or `Deref`. R2/R3 of `docs/design/secure-gate-requested-newtyping-requirements.md`.
- A type-level deny-list for `generic alloc::vec::Vec<u8>` / aliases. Macros cannot see through paths; `dynamic_newtype!` already documents that remainder and this plan does not pretend to close it.
- Changing `dynamic_newtype!`'s generic arm, except as a wording precedent in A4.
- Teaching `generic` to mean a type parameter on the generated struct (`Poly<T>`). The generated type stays monomorphic.

## Backport

Not assumed. `release/0.8` already has the newtype macros (rc.11) and the alias removal. A is a compile-error for a dominated spelling and is the kind of thing the 0.8 line has taken before; B/C are additive. Decide at implementation time against `docs/audits/pr-182-backport-ledger.md`. Do not copy CI.

## Suggested PR split

1. **A only** — reject arm, trybuild move, CHANGELOG. Closes the audit item.
2. **B** — `Fixed<T>::new_with` + generic-arm forward. Can wait.
3. **C** — only if someone needs `len()` / early `N = 0` on `[i16; N]` without `IntoWrapper`.
