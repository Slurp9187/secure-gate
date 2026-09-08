# Security Considerations for secure-gate

## TL;DR

- **No independent audit** — review the source code yourself before production use.
- **No unsafe code** — `#![forbid(unsafe_code)]` enforced in the library crate.
- **3-tier access model** — explicit hierarchy (prefer Tier 1 scoped methods). Audit Tier 2/3 calls separately.
- **Explicit exposure while held** — while a secret is inside `Fixed`/`Dynamic`, all external access requires `with_secret`/`expose_secret` (or mutable equivalents); those two types implement no `Deref`/`AsRef`. Internal impls (`Clone`, `Serialize`) access `.inner` directly by design — they require opt-in marker traits and do not expose secrets to callers.
- **Extraction is a hand-off** — `into_inner` transfers ownership of the plain value and **ends protection**: what you get back is an ordinary `[u8; N]` / `String` / `Vec<T>` with no zeroize-on-drop and no redacted `Debug`. Encoding is the exception: every encoder returns `EncodedSecret`, which keeps zeroize-on-drop and a redacted `Debug` for the buffer it owns, because an encoded secret is a second full copy of the secret. Copies you make through its `Deref` are ordinary values. See [Where accident-prevention ends](#where-accident-prevention-ends).
- **Zeroization on drop** — full buffer (incl. spare capacity) is wiped (inner type must implement `Zeroize`).
- **Timing-safe equality** — use `.ct_eq()` (`ct-eq` feature); `==` is deliberately not implemented.
- **Opt-in risk** — cloning/serialization requires marker traits (`CloneableSecret`/`SerializableSecret`).

This document outlines the security model, design choices, strengths, limitations, and review guidance.

## What secure-gate does NOT protect against

- **Process compromise / arbitrary memory read** — wrappers offer no defense if an attacker can read process memory.
- **OS swap, page files, core dumps** — secrets may be paged to disk; use `mlock` or encrypted swap at the OS level.
- **`panic = "abort"` / SIGKILL / hard crash** — `Drop` impls do not run; secrets are not cleared.
- **`static` secrets** — Rust does not invoke `Drop` on statics; `Fixed::new` in a `static` is never zeroized.
- **Copies made by caller code** — after `expose_secret()` or serialization, the caller holds ordinary non-zeroized memory.
- **Anything past `into_inner()`** — extraction hands you the plain value and ends protection. It is not wiped for you, and its `Debug` is not redacted.
- **Encoded/serialized output** — every encoder (`to_hex()`, `to_base32()`, `to_base64url()`, `try_to_bech32()`, `try_to_bech32m()`) returns `EncodedSecret`: `Zeroizing<String>` with a redacted `Debug` and no `Display`, so the encoded copy is wiped on drop. serde `Serialize`, by contrast, produces full secrets in ordinary non-zeroizing buffers that this crate cannot reach. `EncodedSecret::into_inner()` is the named call that hands you an unprotected `String`.
- **All side channels beyond equality timing** — cache, power, EM, and branch-predictor attacks are out of scope.
- **Allocation-based DoS from deserialization** — `MAX_DESERIALIZE_BYTES` is a post-materialization bound only; the upstream deserializer may allocate arbitrarily first.
- **Stack/register residue** — temporaries, FFI boundaries, and compiler spills are outside wrapper control.

## Inherent Rust Limitations

These three limitations are inherent to systems languages with a stack, a
growable heap, and an OS that pages memory. They are **not unique to
`secure-gate`** — `secrecy`, `zeroize`-wrapped collections, C/C++ secret
crates, and Go's `memguard` all share the same threat model. The crate
documents them honestly rather than overclaiming.

### 1. Stack-move residue (`Fixed<T>`)

When a `Fixed<T>` is moved (returned, passed by value, stored into a
struct field), the bytes are bitwise-copied to the new location and the
**original stack slot retains the original bits** until a later stack
frame overwrites them. `ZeroizeOnDrop` only fires on the *current*
location. The Rust language has no facility to direct the compiler to
zero an out-of-scope stack slot.

**Recommended patterns:**

- Use [`Fixed::new_with`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#method.new_with) instead of [`Fixed::new`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#method.new) to write secret material directly into the wrapper's storage — eliminates the construction-site stack temporary.
- Pass `&Fixed<T>` / `&mut Fixed<T>` by reference rather than `Fixed<T>` by value. Keep the wrapper short-scope.
- For long-lived secrets, prefer [`Dynamic<T>`](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html) built with `new_with` or a decode constructor — the buffer is heap-only and never passes through a stack temporary. (`Dynamic::new(v)` still moves `v` in by value.)
- For address-stability needs (FFI, self-referential structs), users may pin the wrapper at the call site: `let key = core::pin::pin!(Fixed::new_with(|a| …));`. This is opt-in; the crate does not impose pinning by default because it would break idiomatic use (returning, storing).

### 2. Heap-reallocation residue (`Dynamic<Vec<T>>` / `Dynamic<String>`)

When a `Vec<T>` or `String` grows past its current capacity, the
standard library allocates a new buffer, memcpys the contents, and frees
the old buffer **without zeroing**. `ZeroizeOnDrop` only zeros the
*currently held* allocation. The freed bytes remain readable in heap
memory until the allocator reuses or unmaps the page; they survive into
core dumps and swap.

**What the crate now handles, and what it cannot.** Where `secure-gate` owns the
growth it wipes the outgoing buffer: `std::io::Write` on `Dynamic<Vec<u8>>`
allocates the larger buffer, copies, zeroizes the old one (contents *and* spare
capacity), and only then releases it. This is verified by an allocator-level
regression test (`tests/heap_zeroize.rs`,
`check_write_growth_orphan_zeroed`) that inspects the freed page at the moment
of growth rather than only at drop.

It cannot do the same for `with_secret_mut` / `expose_secret_mut`: those hand the
caller a `&mut Vec<T>` or `&mut String`, and a `push` / `extend` / `insert` that
grows it reallocates entirely outside this crate. **That case remains a real
limitation**, and the patterns below are the mitigation.

**Recommended patterns:**

- For **known-size key material**, prefer [`Fixed<[u8; N]>`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html) (no allocation) or `Dynamic<[u8; N]>` (heap-only, fixed size — no realloc surface).
- For **bounded-size variable-length secrets**, pre-size with `Vec::with_capacity(MAX)` / `String::with_capacity(MAX)` *before* wrapping in `Dynamic`, then only perform capacity-stable mutations through `with_secret_mut`.
- For **infrequent updates**, replace the entire wrapper rather than mutating in place: `dyn_secret = Dynamic::new_with(|v| …)` — the old `Dynamic` zeroizes its buffer on drop.
- For **deployment-level remediation**, install a zero-on-deallocate global allocator such as [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) in the final binary, or rely on OS facilities (Linux `init_on_free=1`, hardened allocators). These are process-wide operational choices rather than a per-crate feature.

A custom-allocator-parameterized `Dynamic<T, A>` (analogous to C++'s
`std::vector<T, ZeroingAllocator<T>>`) would resolve this at the type
level but currently requires nightly Rust (`allocator_api`) and `unsafe`
code. `secure-gate` does not enable it; users with strict realloc-residue
requirements should adopt the global-allocator approach above.

### 3. Swap / core dumps / external memory exposure

Process memory may be paged to disk (swap, hibernation) or written to a
core dump on crash. Once written, zeroization-on-drop in the running
process is irrelevant — the bytes already left the process's address
space. This applies identically to C, C++, Go, and Rust; it is OS-level
and outside any in-process library's reach.

**Recommended patterns (deployment-level):**

- Use **encrypted swap** (default on most modern Linux distributions, FileVault on macOS, BitLocker on Windows).
- Disable core dumps for secret-holding processes: `prctl(PR_SET_DUMPABLE, 0)` on Linux, `setrlimit(RLIMIT_CORE, 0)` for the whole process, or container `--ulimit core=0`.
- `mlock` / `mlockall` to prevent specific allocations from being paged out — at the cost of pinning physical memory and consuming the process's lock budget.
- Disable hibernation on machines that hold long-lived keys, or ensure hibernation storage is encrypted.

`secure-gate` treats all three of these mitigations as deployment
configuration. The crate does not call `mlock` or set process flags
itself.

## Audit Status

`secure-gate` has **not** undergone an independent security audit.

The crate is intentionally small and relies on well-vetted dependencies. `zeroize` is
the **only** unconditional one — with default features a full `cargo tree` is two lines
— and every other entry below arrives solely with the feature that names it. No
proc-macro crate is pulled in unless you enable `serde`; `Display` and `Error` for the
types in `src/error.rs` are hand-written rather than derived.

- `zeroize` — memory wiping (always)
- `subtle` — constant-time comparison primitives
- `rand_core` + `getrandom` — secure randomness (via `rand` feature)
- `base16ct` — constant-time hex encoding/decoding (RustCrypto)
- `base32ct` — constant-time Base32 encoding/decoding (RustCrypto)
- `base64ct` — constant-time base64url encoding/decoding (RustCrypto)
- `bech32` — Bech32 / Bech32m checksum encoding

**Before production use**, review:

- Source code
- Tests:
  - `tests/zeroize_tests.rs` — semantic layer: verifies drop order, API-visible state, and spare-capacity targeting via `PanicOnNonZeroDrop`
  - `tests/heap_zeroize.rs` — physical layer: verifies heap bytes are zeroed before deallocation via `ProxyAllocator` interception
  - `tests/ct_eq_tests.rs` and `tests/proptest_suite/` — timing-safe equality coverage
- Dependency versions and their security history

## 3-Tier Access Model
All secret access follows this explicit hierarchy (the table below expands on these tiers):

- **Tier 1 — Scoped borrow (preferred)**: `with_secret` / `with_secret_mut` — borrow ends when closure returns, minimizing exposure.
- **Tier 2 — Direct reference (escape hatch)**: `expose_secret` / `expose_secret_mut` — long-lived references; use only for FFI or third-party APIs requiring `&T`/`&mut T`.
- **Tier 3 — Owned consumption**: `into_inner` — returns the plain `T`; **protection ends at the call**. Nothing is copied (an inert sentinel is left for the wrapper's `Drop`), but the value you receive is not wiped for you. Audit separately: `grep into_inner`.

- **Streaming I/O (via `as_reader()`)**: `DynamicReader` implements `std::io::Read` by copying secret bytes into caller-provided buffers through `with_secret` internally. The caller owns zeroization of the destination buffer. `std::io::Write` on `Dynamic<Vec<u8>>` flows data **into** the wrapper, so it is not a *read* surface — but writing past capacity used to leave the outgoing buffer unwiped (see [Heap-reallocation residue](#2-heap-reallocation-residue-dynamicvect--dynamicstring)). That path now grows by hand and zeroizes the old allocation before releasing it. Requires the `std` feature.

**Audit note**: Tier 2, Tier 3, and `as_reader` calls do not appear in simple `expose_secret` grep sweeps and must be reviewed independently.

## Where accident-prevention ends

The tiers above describe **holding** a secret. They stop at the wrapper boundary, and
the crate makes two different promises on either side of it.

| Obligation | Scope |
| ---------- | ----- |
| Accidents must not compile | While the secret is held in `Fixed`/`Dynamic`. Ends at the named extraction. |
| Documented behavior must be accurate | Everywhere, forever. |

`into_inner`, `expose_secret`, and `EncodedSecret::into_inner` are named exits. You typed the name,
the call site is grep-able, and ownership transfers to you. Past that point the crate is
not trying to follow the bytes — that would mean either another wrapper or a false claim.

**What the output wrapper still does**: `EncodedSecret` zeroizes the buffer it owns on
drop, and prints `[REDACTED]` for `Debug`.

**What extraction does not do**: keep protecting. `into_inner` hands back a plain value,
and `EncodedSecret` derefs to `str`, so all of the following produce ordinary, untracked
plaintext, by design:

```rust,ignore
let plain = key.into_inner();         // [u8; 32] — plain: not wiped, not redacted
let enc = other_key.to_hex();         // EncodedSecret — wiped on drop, Debug redacted
let s: String = enc.to_string();      // via Deref<Target = str> — untracked
```

Two specific consequences:

- **`Debug` redaction survives neither extraction nor a deref.** `format!("{:?}", key)`
  prints `[REDACTED]`, but `format!("{:?}", key.into_inner())` prints the secret:
  redaction is a property of the wrapper, not of `T`. One level down it is the same
  story — `format!("{:?}", enc)` prints `[REDACTED]`, `format!("{:?}", &*enc)` prints
  the encoded secret.
- **`EncodedSecret::into_zeroizing()` is a downgrade.** It returns `zeroize::Zeroizing<String>`, whose `Debug`
  is not redacted (`zeroize` 1.8/1.9 derive it; a future release may change the
  rendering). Zeroize-on-drop is preserved, redaction is not. It exists for APIs that
  demand a `Zeroizing<T>` by name. Note that this crate does not re-export `zeroize`, so
  naming that return type means taking a compatible `zeroize` dependency yourself.

An encoded secret is still the whole secret in a different alphabet. `EncodedSecret` is a
zeroizing `String` buffer with redacted `Debug` — not a redaction of the value.

## Core Security Model


| Property                       | Guarantee / Design Choice                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Explicit exposure              | Private inner fields; all caller-facing access via audited methods (`expose_secret`, `with_secret`). Internal impls (`Clone`, `Serialize`) access `.inner` directly but require opt-in marker traits; `ConstantTimeEq` routes through `expose_secret()` with a `RevealSecret` bound. |
| Scoped exposure (preferred)    | Closures limit borrow lifetime; prevents long-lived references                                                     |
| Direct exposure (escape hatch) | `expose_secret()` / `expose_secret_mut()` — grep-able, auditable                                                   |
| No implicit leaks (while held) | `Fixed`/`Dynamic` implement no `Deref`, `AsRef`, `Copy`, or `Clone` (unless `cloneable` + marker). Output wrappers deref by design — see [Where accident-prevention ends](#where-accident-prevention-ends). |
| Zeroization                    | Full allocation always wiped on drop; includes `Vec`/`String` spare capacity (inner type must implement `Zeroize`) |
| Timing safety                  | `ConstantTimeEq` (`.ct_eq()`) — deterministic constant-time comparison via `expose_secret()`. Avoid `==`.          |
| Opt-in risky features          | Cloning/serialization gated by marker traits (`CloneableSecret`, `SerializableSecret`)                             |
| Redacted debug                 | `Debug` on `Fixed`, `Dynamic`, the generated newtypes and `EncodedSecret` always prints `[REDACTED]`. It is a property of the wrapper: values obtained through `into_inner` or a deref print normally, and error types print their own contents. |
| No unsafe code                 | `#![forbid(unsafe_code)]` enforced in the library crate                                                            |


## Feature Security Implications


| Feature             | Security Impact                                                                                                                                                           | Recommendation                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `alloc` *(default)* | Enables `Dynamic<T>` + full zeroization of `Vec`/`String` spare capacity. Use `default-features = false` for no-heap builds — the crate is `#![no_std]` without the `std` feature, verified in CI by cross-building for `thumbv7em-none-eabihf`. | Enable unless on embedded/pure-stack target                                                                                      |
| `std`               | Full `std` support (implies `alloc`). Adds two surfaces: `as_reader()` copies secret bytes into caller-owned buffers that this crate cannot wipe, and the `Write` impl on `Dynamic<Vec<u8>>` grows by hand so it can zeroize the outgoing buffer. Audit `as_reader` call sites like Tier 2 access. | Optional; `alloc` is sufficient for most targets                                                                                 |
| `ct-eq`             | Timing-safe direct byte comparison (`.ct_eq()`)                                                                                                                           | Strongly recommended; avoid `==`                                                                                                 |
| `rand`              | `from_random()` uses system `SysRng` (`rand` 0.10) and panics on failure; `from_rng()` accepts caller-supplied `TryRng + TryCryptoRng` and returns `Result`            | Use trusted entropy sources; prefer `from_rng()` where RNG failure should be handled explicitly                                 |
| `serde-deserialize` | Decodes to inner type; temporary buffers use `zeroize::Zeroizing` (zeroized on rejection too). `Fixed<[u8; N]>` rejects over-length sequences before its buffer can grow, so no unzeroized realloc residue is left behind. 1 MiB default limit (`MAX_DESERIALIZE_BYTES`). See allocation notes below. | Enable for trusted deserialization sources; set a tight limit for untrusted input and enforce transport-level size caps upstream |
| `serde-serialize`   | Opt-in export via marker trait; audit all implementations                                                                                                                 | Enable sparingly; monitor exfiltration risk                                                                                      |
| `encoding`          | Meta: enables all encoding sub-features (hex, base32, base64url, bech32, bech32m). Encoding traits require `alloc` (they return `EncodedSecret`, which owns a `String`); `Fixed::try_from_*` decoding works without `alloc`. | Enable per-format instead for minimal surface                                                                                    |
| `encoding-hex`      | Hex encoding/decoding via `base16ct` (constant-time). `ToHex`/`FromHexStr` require `alloc`; `Fixed::try_from_hex` is no-alloc. | Validate inputs upstream; prefer `try_from_hex`                                                                                  |
| `encoding-base32`   | Base32 encoding/decoding via `base32ct` (constant-time), RFC 4648 §6 — uppercase and unpadded; lowercase and `=` padding are rejected. `ToBase32`/`FromBase32Str` require `alloc`; `Fixed::try_from_base32` is no-alloc. | Validate inputs upstream; prefer `try_from_base32`                                                                               |
| `encoding-base64`   | Base64url encoding/decoding via `base64ct` (constant-time). `ToBase64Url`/`FromBase64UrlStr` require `alloc`; `Fixed::try_from_base64url` is no-alloc. | Validate inputs upstream; prefer `try_from_base64url`                                                                            |
| `encoding-bech32`   | Bech32/BIP-173 and Bech32m/BIP-350 encoding/decoding. `ToBech32`/`FromBech32Str` require `alloc`; `Fixed::try_from_bech32` is no-alloc via `byte_iter()` drain. HRP-checked decode paths validate the HRP *before* materializing any payload bytes, so a mismatch never leaves decoded secret material in unzeroized memory. HRP comparison is non-constant-time (HRP is public metadata — timing leak is acceptable). | Validate inputs upstream; test empty/invalid HRP                                                                                 |
| `cloneable`         | Opt-in cloning via marker trait; increases exposure surface                                                                                                               | Use minimally; prefer move semantics                                                                                             |
| `full`              | All features enabled — convenient but increases attack surface                                                                                                            | Development only; audit for production                                                                                           |


#### `serde-deserialize` — Allocation & Limit Notes

`MAX_DESERIALIZE_BYTES` (default 1 MiB) and `deserialize_with_limit` are enforced **after** the upstream deserializer has fully materialized the payload — they are result-length acceptance bounds, not pre-allocation guards. For untrusted input, enforce size limits at the transport or parser layer upstream to prevent allocation-based DoS.

## Best Practices

> See the [TL;DR](#tldr) for the shortest version of the most important points.

- Prefer **Tier 1 scoped methods** (`with_secret`/`with_secret_mut`) in application code to minimize lifetime.
- Audit every Tier 2 (`expose_*`) and Tier 3 (`into_inner`) call site separately — they do not appear in simple `expose_secret` grep sweeps.
- Use `alloc` (default) for `Dynamic<T>` zeroization; disable for pure-stack `Fixed<T>` builds.
- Use `.ct_eq()` (`ct-eq` feature) for comparisons; avoid `==`. Bound untrusted input size at the transport/parser layer.
- Audit all `CloneableSecret`/`SerializableSecret` implementations.
- Validate inputs before encoding/decoding or using format-specific traits.
- For encoding: every encoder returns `EncodedSecret`, which stays wiped until it drops. Read it with `&*encoded` (it derefs to `str`); call `.into_inner()` only when an API demands an owned `String`, which is the named moment protection ends.
- Monitor dependencies for CVEs.
- Treat secrets as radioactive — minimize exposure surface.

## Module-by-Module Security Notes

> Security invariants (no `Deref`/`AsRef`, `Debug` prints `[REDACTED]`, zeroize on drop, opt-in clone/serialize) are documented in full on the [`Fixed`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html) and [`Dynamic`](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html) rustdoc. This section focuses on weaknesses and mitigations not visible from the API surface.

### Wrappers (`dynamic.rs`, `fixed.rs`)

**Potential weaknesses**

- Long-lived `expose_secret()` references can defeat scoping
- Macro-generated aliases lack runtime size checks
- Certain error variants may indirectly leak length information (e.g. wrong decoded length).
  In most real-world usage (logging, API responses), length is already public metadata anyway (e.g. key length in JWT headers, signature length). Still, contextualize or redact errors when possible.
- `Fixed<T>` decode constructors previously used `copy_from_slice` into a separate
  stack-allocated `[0u8; N]` before wrapping. **This has been mitigated**: all
  library-internal decode paths (`try_from_hex`, `try_from_base32`,
  `try_from_base64url`, `try_from_bech32*`, `TryFrom<&[u8]>`) and the RNG constructors
  (`from_random`, `from_rng`) now use `Fixed::new_with`, which writes directly into the
  wrapper's storage and avoids the intermediate slot. The `new(value)` constructor still
  accepts a pre-constructed array and may produce a brief stack temporary (compiler often
  eliminates it at opt-level ≥ 1 with `#[inline(always)]`). `Dynamic<T>` avoids all stack
  involvement via `from_protected_bytes` + `mem::swap` (heap-only path).
- **`static` secrets are never zeroized.** `Fixed::new` is `const fn`, so
  `static SECRET: Fixed<[u8; 32]> = Fixed::new([...]);` compiles without warning.
  Rust does not invoke `Drop` on program-scope statics during the lifetime of the
  process. The `ZeroizeOnDrop` guarantee only applies to values that are dropped in
  the normal sense (stack unwinding, scope exit). Do not store secrets in statics.
- **`Dynamic::into_inner` allocates a small sentinel `Box` (24 bytes on 64-bit).**
  This is a new availability surface: on pathologically memory-pressured systems the
  sentinel allocation can OOM. Confidentiality is preserved — if `Box::new` panics
  before the swap, `self.inner` still holds the real secret and `Dynamic::drop` zeroizes
  it during unwind. `Fixed::into_inner` is zero-cost (no allocation).
- **`into_inner` returns the plain value; protection ends there.**
  Earlier releases returned an `InnerSecret<T>` that kept wiping. That type is gone: it
  was a newtype over `Zeroizing<T>` whose only distinct behaviour was escaping this
  crate's own no-`Deref` rule. If you want the protection to continue, keep the wrapper,
  or move the value into `zeroize::Zeroizing` yourself. The superseded wording is kept
  as an HTML comment in the source of this file, where it is visible to `git blame` but
  not to a reader of the rendered page.

  <!-- historical: InnerSecret<T> restored the wrapper-level `[REDACTED]` invariant after ownership
  transfer by implementing `Debug` as constant redaction. Use
  `InnerSecret::into_zeroizing()` only when interoperability required the raw
  `Zeroizing<T>` wrapper. -->
- **`panic = "abort"` builds disable zeroization on panic.** When `panic = "abort"`
  is set in a profile, Rust aborts the process immediately on panic without running
  any `Drop` implementations. Secrets held in `Fixed<T>` or `Dynamic<T>` at the
  moment of a panic will not be zeroized before the process exits. This is an
  inherent limitation of the `zeroize` ecosystem — `zeroize`, `secrecy`, and other
  crates share the same constraint. Prefer `panic = "unwind"` (the default) in
  security-sensitive builds.
- **`Dynamic<Vec<T>>` / `Dynamic<String>` mutation via reallocation leaves the
  *previous* heap buffer unzeroized.** `Dynamic<T>` zeroizes the *currently held*
  allocation on drop (including `Vec` / `String` spare capacity). Mutation
  operations through `with_secret_mut` / `expose_secret_mut` that exceed the
  current capacity (`push`, `push_str`, `extend`, `reserve`, `resize` past
  `capacity()`, `insert`, etc.) cause `Vec` / `String` to allocate a new buffer,
  copy the data, and free the old one through the standard allocator — *without
  zeroizing the old buffer first*. The freed bytes remain readable in the heap
  until the allocator reuses or unmaps the page, and they survive into core
  dumps and swap.

  **If your threat model includes process-memory disclosure (heap scrape, swap,
  core dump) of secrets that have been mutated in place after construction,
  avoid capacity-changing mutations on `Dynamic<Vec>` / `Dynamic<String>`.**
  Either:

  - pre-allocate to the maximum needed size with `Vec::with_capacity` /
    `String::with_capacity` before wrapping, then mutate in place — every
    capacity-stable mutation rewrites bytes in the same buffer, which is
    zeroized on drop;
  - use `Fixed<[u8; N]>` for known-size secrets (no realloc surface; the
    allocation is fixed and zeroized on drop); or
  - replace the wrapper with a fresh `Dynamic::new_with(...)` rather than
    mutating in place — the old `Dynamic` zeroizes its buffer on drop.

  This is a fundamental limitation of `Vec<T>` / `String` in Rust — the
  standard library exposes no allocator hook to zeroize-on-realloc. The same
  limitation applies to `secrecy`, `zeroize`-wrapped collections, and every
  other secret wrapper around the standard collections; a custom-allocator
  workaround exists but trades off significant complexity and is not enabled
  by default in this crate. **`Fixed<T>` is exempt** — it has no realloc surface.

  For stricter deployment threat models, handle this below the library layer:
  install a zero-on-dealloc global allocator such as
  [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) in the final
  binary (the recommended approach when downstream code controls the global
  allocator), use OS or allocator zero-on-free facilities where available
  (for example Linux `init_on_free=1` or hardened allocators), disable core
  dumps for secret-holding processes, and ensure swap / hibernation storage is
  encrypted. These are process-wide operational choices, so `secure-gate` treats
  allocator-level zeroization as deployment configuration rather than a crate
  feature. See the "Inherent Rust Limitations" section above for the broader
  context.

**Mitigations**

- **For accessing secrets:** prefer the scoped `with_secret()` / `with_secret_mut()` closures
  over `expose_secret()` / `expose_secret_mut()` — they keep the exposed reference tightly
  bound and make accidental long-lived borrows visible at the call site.
- **For constructing secrets:** prefer `Fixed::new_with(|arr| { ... })` or
  `Dynamic::<Vec<u8>>::new_with(|v| { ... })` / `Dynamic::<String>::new_with(|s| { ... })`
  over `Fixed::new(value)` / `Dynamic::new(value)` when constructing from computed data
  inline — these write directly into the wrapper's storage and avoid any intermediate copy.
  `Dynamic<T>` remains the strictest option: its buffer lives only on the heap. That is
  a property of the buffer, not of every value that ever reaches it — `Dynamic::new(v)`
  and `From<T>` take `v` by value, and `into_inner` returns it by value, so those three
  do put the secret on the stack briefly. The `new_with` and decode constructors
  (`from_protected_bytes` + `mem::swap`) are the paths with no stack step at all.

**Security-first construction and access patterns**

Just as `with_secret` / `with_secret_mut` are the recommended scoped methods for *accessing*
secrets — keeping the exposed reference tightly bound to the closure lifetime —
`Fixed::new_with` is the recommended constructor for *building* `Fixed` secrets when
minimizing stack residue matters. It writes secret material **directly** into the wrapper's
own storage, eliminating the intermediate stack temporary that can exist with the ergonomic
`new(value)` constructor.

`Dynamic<T>` is already heap-only (`from_protected_bytes` + `mem::swap`), so its
`new_with` variants (`Dynamic::<Vec<u8>>::new_with` / `Dynamic::<String>::new_with`)
exist purely for API symmetry — not because `Dynamic` carries any stack-residue risk.
If stack residue is a concern, `Dynamic<T>` remains the strictest overall choice.

For high-assurance `Fixed` construction, prefer:

- `Fixed::new_with(|arr| { … })` over `Fixed::new(value)`

The regular `new(value)` constructors and `expose_secret` / `expose_secret_mut` remain
available as convenient defaults and auditable escape hatches respectively. This mirrors a
consistent "scoped / minimal lifetime" philosophy across both construction and access — the
same defensive mindset applied throughout the crate.

- Audit all `expose_secret()` calls
- Contextualize errors to avoid side-channel information
- Never store a wrapper in a `static` — use local variables or heap-allocated structs instead
- Keep the default `panic = "unwind"` profile in security-sensitive builds; if `panic = "abort"` is required, document and accept the constraint that secrets may not be cleared on panic

Zero-cost claim: performance is indistinguishable from raw arrays (see benchmarks in the test suite and `size_of_val` assertions); the wrapper adds no runtime overhead beyond the required zeroization on drop.

### Traits (`traits/`)

**Potential weaknesses**

- Generic impls assume caller trustworthiness

**Mitigations**

- Audit every `CloneableSecret` / `SerializableSecret` impl — each is a deliberate security decision
- Validate inputs before trait usage

### Encoding/Decoding (Traits & Errors)

#### Untrusted Input & Format Enforcement

- Validate and sanitize all inputs before any decoding operation
- Use specific traits (`FromBech32Str`, `FromHexStr`, `FromBase32Str`, `FromBase64UrlStr`) when the expected format is known — they enforce strict parsing rules. `FromBase32Str` accepts only the RFC 4648 §6 uppercase, unpadded form; lowercase and `=` padding are rejected rather than normalized. Note that Base32 decoding is **not injective**: non-canonical trailing bits are ignored rather than rejected, so distinct strings (`"MZ"` and `"MY"`) decode to identical bytes — never treat a successful decode as proof that two encoded strings were equal
- Fuzz parsers and boundary cases in CI; treat all decoding input as untrusted
- Temporary decode buffers for `Dynamic<Vec<u8>>` and `Dynamic<String>` constructors and `Deserialize` impls are wrapped in `zeroize::Zeroizing` — buffers are zeroized even if a panic occurs between a successful decode and wrapper construction (#96, #97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization rejects payloads exceeding `MAX_DESERIALIZE_BYTES` (1 MiB); oversized buffers are zeroized before deallocation. Use `deserialize_with_limit` for custom ceilings. (#99)

#### Audit Surfaces

All secret materialization requires an explicit call. Use `rg`, `grep -rn`, or your editor's project-wide search for these method names:

```
expose_secret  expose_secret_mut  with_secret  with_secret_mut
into_inner  into_zeroizing  as_reader
to_hex  to_hex_upper  to_base32  to_base64url
try_to_bech32  try_to_bech32m  try_to_bech32_sized  try_to_bech32m_sized
try_from_hex  try_from_base32  try_from_base64url  try_from_bech32  try_from_bech32m
```

`into_zeroizing` and `as_reader` materialize secret bytes as surely as the rest:
the first hands off an unredacted `Zeroizing<String>`, the second copies into a
buffer the caller owns and must wipe. The `try_from_*` constructors are the reverse
direction, and belong in the sweep because they are where untrusted input enters.

**Note:** `into_inner` does not appear in an `expose_secret*`-only sweep — audit it
separately. It consumes the wrapper and transfers ownership of the **plain** value:
protection ends at the call, and the caller owns the secret's lifetime from there.

Encoding traits (`ToHex`, `ToBech32`, etc.) are **explicit secret exposure** — they will not appear in an `expose_secret`-only sweep, so audit them separately.

For `expose_secret` + encode: chaining immediately is safe; binding to a named variable that outlives the encoding call is the risk — use only for FFI or APIs requiring a raw `&[u8]` slice. Prefer `Fixed::try_from_bech32` / `Dynamic::try_from_bech32` (and `*_bech32m`) over `_unchecked` variants to prevent cross-protocol confusion attacks (BIP-173 vs BIP-350).

#### Error Metadata (build-invariant)

Error enums have **identical shapes and messages in debug and release builds** — no variant is gated on `cfg(debug_assertions)`. (Earlier release candidates stripped error detail in release builds; that made downstream `match` code compile differently per profile and was removed for v0.9.0.)

What errors may and may not carry:

- **Numeric length metadata** (`InvalidLength { expected, got }`) is present in all builds. Expected lengths are compile-time protocol parameters (key sizes, nonce sizes) and actual lengths derive from the caller's own input — neither is secret in this crate's threat model.
- **Input-derived strings are never captured**, in any build: no received-HRP text, no encoding "hints", no payload bytes. All error types are heap-free and `Copy`.
- All error enums (and their struct variants) are `#[non_exhaustive]`, so variants and fields can be added without a semver-major bump.

If even coarse error categories or length metadata are sensitive in your deployment (attacker fingerprinting, strict oracle avoidance), redact errors at the logging/response boundary — the library deliberately does not vary its behavior by build profile.

## Encoding: One Protected Output Type

Encoding methods on `Fixed<[u8; N]>`, `Dynamic<Vec<u8>>`, and the encoding traits (`ToHex`, `ToBase32`, `ToBase64Url`, `ToBech32`, `ToBech32m`) all return the same protected type:

| Method | Returns | Zeroized on drop? |
|---|---|---|
| `to_hex()`, `to_hex_upper()`, `to_base32()`, `to_base64url()` | `EncodedSecret` | Yes |
| `try_to_bech32()`, `try_to_bech32m()`, and their `_sized::<N>` forms | `Result<EncodedSecret, _>` | Yes |
| `EncodedSecret::into_inner()` | `String` | **No — protection ends here** |

There is no unprotected encoder. Earlier releases paired each method with a `*_zeroizing` twin and made the *unprotected* one the short name; that pairing is gone. An encoded secret is a second full copy of the secret in a longer, human-readable alphabet, so it is wiped by default and the unprotected form costs a named call.

`EncodedSecret` wraps `Zeroizing<String>`, redacts `Debug` as `[REDACTED]`, and zeroizes the string buffer on drop. Keep values in this form as long as possible.

**Encoding an already-encoded secret is a compile error.** The encoder traits are
implemented for `AsRef<[u8]> + EncodableBytes`, and `str` does not implement
`EncodableBytes`. Without that second bound `encoded.to_hex()` compiled — `EncodedSecret`
derefs to `str`, and `str: AsRef<[u8]>` satisfied the old blanket — and it hex-encoded the
*encoded text*, so a 32-byte key came back as 124 characters with nothing in the signature
or the name to suggest anything was wrong. `"text".to_hex()` was the same accident from the
other direction. Both are rejected at compile time now; write `.as_bytes()` when the UTF-8
really is what you meant. `EncodableBytes` is a public opt-in marker, so your own
byte-shaped newtype can implement it.

**Escape hatches:**

- `EncodedSecret::into_inner()` → returns a plain `String`, ends zeroization protection. Use only when an API requires ownership of `String`.

- `EncodedSecret::into_zeroizing()` → returns `Zeroizing<String>`. Zeroize-on-drop is preserved; the redacted `Debug` is **not**, because `zeroize::Zeroizing` derives its own. Prefer this when a downstream API accepts `Zeroizing<String>` by name.

**Bech32 code length.** The plain `try_to_bech32` / `try_from_bech32` methods use
`BECH32_CODE_LENGTH` (1023) — the length of the bech32 BCH code, within which the
checksum's guaranteed detection of up to four character errors holds. The `_sized::<N>`
methods take that bound as a parameter. **Choosing `N` above 1023 forfeits the
guarantee**: the same 30-bit checksum is stretched over a longer message, leaving an
integrity check with no proven detection bound. It is still computed and still verified.
Size `N` with `bech32_code_length(hrp_len, payload_bytes)`; the choice is spelled at the
call site, so `grep _sized` finds every place it was made.

## Vulnerability Reporting

- **Preferred**: GitHub private vulnerability reporting (Repository → Security → Report a vulnerability)
- **Alternative**: Public issue or draft
- **Expected response**: Acknowledgment within 48 hours; coordinated disclosure
- **Public disclosure**: After fix is released and users have reasonable time to update

## Disclaimer

This document reflects design intent and observed properties as of the current release.

**No warranties are provided**. Users are solely responsible for their own security evaluation, threat modeling, and audit.
