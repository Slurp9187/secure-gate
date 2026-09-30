# Sealed memory: encrypting idle secrets in RAM

Status: deferred — not for 0.9.x stable; revisit as an additive, feature-gated minor release
Section it would serve: [`SECURITY.md`](../../SECURITY.md) §3, *Swap / core dumps / external
memory exposure*, and the comparison table beside the `secrets` crate
Reference implementation studied: `sequoia-openpgp` 2.4.1, `src/crypto/mem.rs`
Tracking: #264. Prior discussion: #56 (closed *not planned*; this note revises two of its
assumptions — a stored session key, and guard-returning `expose` access)

`Fixed<T>` and `Dynamic<T>` hold a secret in plaintext for their whole lifetime and wipe it on
drop. Sequoia goes one step further: a secret that is not being used right now is held
**encrypted**, and is decrypted only for the length of one closure call. This note records how
that works, how it would map onto this crate, what it would cost, and why it is not in the
first stable release. It exists so nobody has to repeat the analysis when the question comes
back.

## How sequoia does it

Three layers, all in `src/crypto/mem.rs`:

| Type | Role |
|---|---|
| `Protected` | Exact-size heap buffer (`Box<[u8]>` leaked into a `*mut [u8]`), `memsec::memzero` on drop, never reallocated. |
| `Encrypted` | `{ ciphertext: Protected, salt: [u8; 32], plaintext_len: usize }`. Plaintext exists only inside `map(|p: &Protected| …)`. |
| `crypto::Password`, `SessionKey`, unlocked key material (`Unencrypted { mpis: mem::Encrypted }`) | The secret-bearing types built on the two above. |

### Where the key lives: nowhere

The sealing key is never stored. What is stored is the material it is recomputed from, in two
places:

1. **The pre-key — one per process.** A function-local
   `static PREKEY: OnceLock<Result<Box<[Box<[u8]>]>>>` inside a private module
   (`has_access_to_prekey`), filled lazily on first use with four separate 4096-byte heap
   buffers of random bytes (16 KiB total). It is never freed or wiped. It is ordinary heap
   memory: not a `Protected`, not `mlock`ed, no guard pages. The "pages" are plain `Vec`s with
   no page alignment. Module privacy is the only barrier, and that is a code-organisation
   boundary, not a runtime one.
2. **The salt — one per sealed object.** 32 random bytes generated in `Encrypted::new`, stored
   in the struct next to the ciphertext. Not secret.

On every `new` and every `map`:

```text
sealing_key = SHA-256(salt ‖ page0 ‖ page1 ‖ page2 ‖ page3)      // into a SessionKey (Protected)
ciphertext  = AEAD(AES-256, key = sealing_key, nonce = 0…0, aad = ∅)
```

The AEAD mode is `AEADAlgorithm::default()` — OCB where the backend supports it. The all-zero
nonce is safe only because every object has its own random salt and therefore its own key.
The derived key is wiped when the `SessionKey` drops at the end of the call. If the tag fails
to verify, `map` wipes the partial plaintext and panics.

### Why the pre-key is large

The design is OpenSSH's (see the commit linked from sequoia's `Encrypted` docs). Attacks such
as Spectre-class side channels, Rowhammer and cold boot recover memory *with bit errors*. A
32-byte key read with a few flipped bits is still recoverable by search. The sealing key here
depends on all 131,072 bits of the pre-key; one wrong bit anywhere avalanches through SHA-256
and nothing tells the attacker which bit was wrong.

### What it does not protect against

A **clean** read of the address space — a debugger, `/proc/<pid>/mem`, a core dump, a swap
image that captured both halves — yields pre-key, salt and ciphertext together. Sealing narrows
the lossy-readout threat; it is not a substitute for any mitigation in `SECURITY.md` §3.

### Things checked in the 2.4.1 source that are easy to get wrong

These are recorded because third-party summaries of sequoia got them wrong, and because each
is a lesson for this crate.

- **Debug output.** `Protected`'s debug-build `Debug` writes `self.0`, the raw `*mut [u8]`,
  not the bytes. On rustc 1.94.1 that renders as `Pointer { addr: 0x…, metadata: 7 }`: the
  heap address and the **secret's length** leak, the contents do not. Release builds print
  `[<Redacted>]`. `Encrypted`'s derived `Debug` additionally prints `salt` and
  `plaintext_len`.
- **No page locking.** `memsec` is pulled in with `default-features = false`; nothing calls
  `mlock` or `mprotect`. Only `memzero` and `memcmp` are used.
- **Equality decrypts.** `Encrypted::eq` unseals both sides and compares plaintext with the
  constant-time `secure_cmp`. Comparing ciphertexts could not work, since salts differ.
- **`Hash` decrypts too.** `Encrypted::hash` feeds the plaintext into the caller's `Hasher`,
  whose state is never wiped. A small leak worth not copying.
- **Construction wipes its source.** `Protected::from(Vec<u8>)` copies into a fresh
  exact-size box and then zeroes the source `Vec`'s entire *capacity*, not just its length.
- **The "careful" copy is not careful once optimised.** The copy above goes through
  `careful_memcpy`, an element-by-element `iter().zip().for_each` loop, because the source
  notes that `copy_from_slice` "indeed leaks secrets" (presumably through SIMD registers or
  stack scratch left behind by an optimised `memcpy`). Compiled standalone at `-O3` on x86_64
  with rustc 1.94.1, **both** `careful_memcpy` and `copy_from_slice` reduce to a tail call
  `jmp memcpy`: LLVM recognises the loop as a copy idiom. Inlined into sequoia's callers or on
  other targets it may differ — not tested — but it cannot be relied on.
- **Kill switch.** `DANGER_DISABLE_ENCRYPTED_MEMORY` is a `const false`; not a runtime option.

### What carries over without sealing

Three of sequoia's `Protected` techniques look worth adopting on their own. Checked against
this crate, only one needed anything:

| Sequoia technique | Status here |
|---|---|
| Exact-size `Box<[u8]>` that cannot grow, so it can never reallocate | **Already expressible**, now documented. `Dynamic<[u8; N]>` was already recommended for compile-time lengths; `Dynamic<[u8]>` is the runtime-length equivalent — `with_secret_mut` hands out `&mut [u8]`, so growth does not compile. The `Dynamic` module docs gained a table row, the one construction caveat (`Box<[u8]>::from(Vec)` shrinks a `Vec` with spare capacity into a new buffer and frees the old one unwiped, so build it at exact capacity), and a doctest. |
| Zero the source `Vec`'s whole capacity after copying out of it | **Not needed.** Sequoia copies out of the caller's `Vec`, leaving a second plaintext copy to clean up. `Dynamic::new` *moves* the `Vec` in, so the caller's buffer is the one the wrapper holds, and drop already zeroizes its full capacity. Becomes relevant only if a constructor that copies out of an owned `Vec` is ever added. |
| Byte-by-byte copy instead of `memcpy` | **Not adoptable.** Compiles back to `memcpy` (above). A copy that provably leaves nothing in registers or on the stack needs `asm!` or volatile writes, i.e. `unsafe`, which `#![forbid(unsafe_code)]` rules out. The crate's existing answer — avoid the copy: move-in construction, and `new_with` writing into the wrapper's own storage — is the stronger one. |

`Dynamic<[u8]>` is the narrowest `Dynamic` shape. Verified against the crate: construction via
`new` / `From<Box<[u8]>>`, `with_secret`, `with_secret_mut`, `Debug` redaction and `ct_eq`
work; `SecretLen::len` (E0599), `new_with` (E0599) and `into_inner` (`[u8]: SentinelValue`
unsatisfied, E0277) do not. Additive follow-ups if the shape proves popular, none needed for
0.9 stable:

- `impl<T: Zeroize> SecretLen for Dynamic<[T]>`, mirroring the `Dynamic<Vec<T>>` impl.
- `Dynamic::<[u8]>::new_with(len, f)` / `try_new_with` / `from_random(len)`, which would make
  exact capacity the only way to build one and remove the caveat above.
- Encoding and serde impls, as for `Dynamic<Vec<u8>>`.

## Fitting it to `Fixed` and `Dynamic`

### It has to be a separate type, not a mode

| secure-gate access | Sealed equivalent | Possible? |
|---|---|---|
| `with_secret(&self, f)` | unseal into a temporary, call `f`, wipe (sequoia's `map`) | yes |
| `with_secret_mut(&mut self, f)` | unseal, call `f`, re-seal under a **fresh salt** | yes |
| `into_inner(self)` | unseal and return the plain `T` | yes |
| `expose_secret(&self) -> &T` | needs plaintext that outlives the call | **no** |
| `expose_secret_mut(&mut self) -> &mut T` | same | **no** |

`expose_secret` is a required method of `RevealSecret`, so a sealed type cannot implement that
trait without keeping a decrypted copy alive — which is the thing sealing exists to prevent.
Independently, the crate describes `Fixed`/`Dynamic` as zero-overhead; sealing is not (see
[Costs](#costs)). Both point to new types, not a switch on the existing ones.

### It has to be byte-shaped

Encryption needs a byte view of `T`. For an arbitrary `T: Zeroize` that means `unsafe`, and
the crate is `#![forbid(unsafe_code)]`. The sealed family is therefore limited to the shapes
that already carry most of the inherent API:

- `Fixed<[u8; N]>` → `SealedFixed<N>`
- `Dynamic<Vec<u8>>` → `SealedDynamic<Vec<u8>>`
- `Dynamic<String>` → sealed as bytes; unsealing uses `String::from_utf8`, which cannot fail
  on authenticated plaintext and does not copy.

### `SealedFixed<N>` — stays `no_std`, no heap

```rust
pub struct SealedFixed<const N: usize> {
    ct:   [u8; N],   // ciphertext, same length as plaintext
    tag:  [u8; 16],  // detached AEAD tag
    salt: [u8; 32],
}
```

The tag is detached on purpose. Sequoia's single `len + tag` buffer would be `[u8; N + 16]`,
which needs the unstable `generic_const_exprs`. RustCrypto's `encrypt_in_place_detached` /
`decrypt_in_place_detached` avoid it.

`with_secret` unseals into a stack `Fixed<[u8; N]>`, hands `&[u8; N]` to the closure, and lets
`Fixed`'s existing `Drop` wipe it. The temporary *is* the existing wrapper; no new wiping code.

### `SealedDynamic` — heap

Ciphertext in a `Box<[u8]>`; tag and salt inline. Unseal into an exact-capacity
`Dynamic<Vec<u8>>`, again reusing the existing wrapper as the temporary.

`with_secret_mut` inherits the growth hazard measured in
[`heap-residue.md`](heap-residue.md): if the closure grows the `Vec`, the abandoned block
holds plaintext and is freed unwiped. Re-sealing sees the new length but cannot reach the old
block. Either document it, or have `with_secret_mut` hand out a fixed-length `&mut [u8]`
instead of `&mut Vec<u8>`.

### Conversions

- `SealedFixed::from(fixed)` consumes the plain wrapper; its `Drop` wipes the plaintext after
  sealing.
- `sealed.unseal() -> Fixed<[u8; N]>` is `into_inner` in wrapper form.
- Same pair for `Dynamic`.

### The pre-key

Sequoia's `OnceLock` + heap + OS RNG assumes `std`. Two options:

1. **Global pre-key, `std` only.** `static PREKEY: OnceLock<…>` filled via `rand`'s `SysRng`;
   feature `sealed = ["std", "rand", …]`. Matches sequoia and keeps call sites unchanged.
   `OnceLock` is stable since 1.70, inside both release lines' MSRV.
2. **Explicit context, `no_std`-capable.** A caller-created `Prekey` value passed to each
   access: `sealed.with_secret(&prekey, |b| …)`. No global state; works without a heap if the
   caller puts it in a `static`; lets the caller decide when to regenerate (e.g. after
   `fork()`). Costs an argument at every call.

Recommendation: ship (1); add (2) only if someone asks for sealing without `std`.

Unlike sequoia, the pre-key can at least live in a `Fixed<[u8; 16384]>` so it is wiped if ever
dropped. Locking it or excluding it from core dumps (`mlock`, `MADV_DONTDUMP`) needs `unsafe`
or a dependency such as `memsec` or `region`; `SECURITY.md` already warns that naive `mlock`
is unsound, so that is a separate, deliberate decision.

### Crypto choices

- **AEAD:** `chacha20poly1305` — constant-time without AES-NI, `no_std`, RustCrypto like the
  existing encoding dependencies.
- **Key derivation:** `sha2`, `SHA-256(salt ‖ prekey)` as in sequoia. BLAKE2s/BLAKE3 would be
  faster over 16 KiB; SHA-256 is the conservative default.
- **Nonce:** all-zero, valid only because **every** seal draws a fresh salt — including every
  re-seal after `with_secret_mut`. Each mutation therefore costs an RNG call.
- Everything sits behind one optional feature; the default dependency set stays `zeroize` only.

### Other traits

| Trait | Sealed behaviour |
|---|---|
| `Debug` | Fully redacted — no salt, no length. Stricter than sequoia. |
| `ConstantTimeEq` | Unseal both, compare with `subtle`. |
| `Hash` | **Do not implement.** Sequoia's leaks plaintext into the hasher. |
| `Clone` (`cloneable`) | Copy the sealed bytes. Same key, nonce and plaintext, so no nonce reuse. |
| Serde, `ToHex` & co. | Via `with_secret`; unchanged behaviour, one unseal per call. |

## Compatibility: this can be added later without a breaking change

Generic code written against `RevealSecret` should be able to accept sealed types where it
only needs scoped access. The obvious route — moving `with_secret` into a new supertrait of
`RevealSecret` — **is breaking**: a caller that imports only `RevealSecret` and calls
`x.with_secret(..)` on a concrete type no longer finds the method, and external implementors
of `RevealSecret` (which the trait docs invite) must add a second impl.

The additive route is a new trait with a blanket impl:

```rust
pub trait RevealScoped {
    type Inner: ?Sized;
    fn with_secret<F, R>(&self, f: F) -> R where F: FnOnce(&Self::Inner) -> R;
    // with_secret_mut, into_inner …
}
impl<T: RevealSecret> RevealScoped for T { /* forward */ }
impl<const N: usize> RevealScoped for SealedFixed<N> { /* unseal per call */ }
```

The blanket impl and the concrete impl coexist because both the trait and `SealedFixed` are
local to the crate.

**Glob-import hazard.** Every trait is re-exported flat from the crate root (`src/lib.rs`).
If `RevealScoped` joins them with a method also named `with_secret`, a downstream
`use secure_gate::*;` puts both traits in scope and `fixed.with_secret(..)` fails with
`E0034: multiple applicable items in scope`. Either remedy removes it:

- **Keep `RevealScoped` out of the root** — e.g. `secure_gate::scoped::RevealScoped` — and do
  not re-export it there, not even as `use … as _` (underscore imports of traits still reach
  glob importers).
- **Give its method a different name** (e.g. `with_scoped`); it can then live at the root.

### How this was checked

A minimal model of the crate (a `RevealSecret` with `with_secret` + `expose_secret`, `Fixed`,
the blanket `RevealScoped` impl, a `SealedFixed` implementing `RevealScoped` directly) was
compiled as a library with rustc 1.94.1, edition 2024, and exercised by three downstream
binaries:

| Downstream code | Trait at root, same method name | In `scoped` module, not re-exported | Root, renamed method |
|---|---|---|---|
| `use sg::RevealSecret; fixed.with_secret(..)` | compiles | compiles | compiles |
| `use sg::*; fixed.with_secret(..)` | **E0034** | compiles | compiles |
| generic `fn f<S: RevealScoped>` called with `Fixed` and `SealedFixed` | compiles | compiles | compiles |

Re-exporting the module-scoped trait as `pub use scoped::RevealScoped as _;` brought the E0034
back. The model is not the real crate; re-run the same three cases against `src/` when this is
implemented.

## Costs

- **Not zero-overhead.** Each access hashes 16 KiB and runs one AEAD pass; each mutation adds
  an RNG call and a second AEAD pass. Expected to be tens of microseconds per access — **not
  measured**. Benchmark before publishing any number.
- **New crypto surface.** Key derivation, AEAD and nonce discipline in a crate that currently
  performs no cryptography of its own. It needs its own review cycle.
- **Narrow threat model.** Helps against lossy readout only. Must be documented as such, next
  to — not instead of — encrypted swap, disabled core dumps and `mlock`.

## Why it is deferred

The 0.9 stable pitch is zero-overhead, no `unsafe`, `zeroize` as the only required dependency,
and `no_std`. The sealed family breaks the first, the third and (for the global pre-key) the
fourth. It reads better as an opt-in advanced feature on a crate that is already stable than
as part of a first release that then has to explain the exceptions. And since the path above
is additive — new feature, new optional dependencies, new types, a new trait that stays out of
glob imports — nothing in 0.9 needs to change to keep the door open.

## Open questions for when this is picked up

- Benchmark `SealedFixed<32>` access against `Fixed<[u8; 32]>`; decide whether SHA-256 or
  BLAKE3 for the key derivation based on the number.
- Is `SealedDynamic` wanted at all, or does `SealedFixed` cover the real uses (keys, not
  passphrases)?
- `with_secret_mut` on `SealedDynamic`: `&mut Vec<u8>` with the growth caveat, or `&mut [u8]`?
- Pre-key after `fork()`: document, or re-key the child (which means re-sealing everything)?
- Pre-key locking / `MADV_DONTDUMP`: worth a dependency that uses `unsafe`?
- Does anyone need the explicit-context (`no_std`) variant?
