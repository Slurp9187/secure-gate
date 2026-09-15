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
- **OS swap, page files, core dumps** — secrets may be paged to disk; use `mlock` or encrypted swap at the OS level. Applying `mlock` naively is unsound — see [If swap residue is in your threat model](#if-swap-residue-is-in-your-threat-model).
- **`panic = "abort"` / SIGKILL / hard crash** — `Drop` impls do not run; secrets are not cleared.
- **`static` secrets** — Rust does not invoke `Drop` on statics; `Fixed::new` in a `static` is never zeroized.
- **Copies made by caller code** — after `expose_secret()` or serialization, the caller holds ordinary non-zeroized memory. This includes copies made **inside** a `with_secret` closure, where the wrapper is still holding the secret and the code reads as protected: `|p| *p` on `Copy` storage, and `to_vec` / `clone` / `to_string` on any inner type that offers one. No lint detects either. See [4. Copying the secret out of a reveal borrow](#4-copying-the-secret-out-of-a-reveal-borrow).
- **Anything past `into_inner()`** — extraction hands you the plain value and ends protection. It is not wiped for you, and its `Debug` is not redacted.
- **Encoded/serialized output** — every encoder (`to_hex()`, `to_base32()`, `to_base64url()`, `try_to_bech32()`, `try_to_bech32m()`) returns `EncodedSecret`: `Zeroizing<String>` with a redacted `Debug` and no `Display`, so the encoded copy is wiped on drop. serde `Serialize`, by contrast, produces full secrets in ordinary non-zeroizing buffers that this crate cannot reach. `EncodedSecret::into_inner()` is the named call that hands you an unprotected `String`.
- **All side channels beyond equality timing** — cache, power, EM, and branch-predictor attacks are out of scope.
- **Allocation-based DoS from deserialization** — `MAX_DESERIALIZE_BYTES` is a post-materialization bound only; the upstream deserializer may allocate arbitrarily first.
- **Stack/register residue** — temporaries, FFI boundaries, and compiler spills are outside wrapper control.

### If swap residue is in your threat model

The bullet above sends you to `mlock` (POSIX) / `VirtualLock` (Windows) at the OS level.
That is the right answer, and this section exists because the obvious way to apply it is
wrong in a way nothing reports.

**Locks are page-granular, and `munlock` is not reference-counted.** A lock covers the
whole page — typically 4096 bytes — containing the address you named, not the bytes you
asked for. POSIX and Linux both specify that locks do not stack: one `munlock` releases the
page regardless of how many `mlock` calls preceded it.

So the natural call is unsound here:

```rust,ignore
region::lock(&my_secret, size_of_val(&my_secret))?;   // locks a shared page
```

Several heap secrets from the ordinary allocator routinely share a page. Dropping any one
of them unlocks it for **all the others still alive**, silently, while every one of them
still reports itself as protected. On a `Fixed<T>` it is worse than useless: the value
lives on the stack, so you lock a page of unrelated frames, and a move leaves the lock
behind on a slot the secret has vacated.

**Locking correctly means owning the allocation** — one secret per page-aligned,
page-sized region, so nothing shares a page and `munlock` cannot reach a neighbour. That
is a different data structure from `Box<T>`, which is why this crate does not offer it and
why the crates that do are built around their own allocator:

| Crate | What it buys |
|---|---|
| [`secrets`](https://crates.io/crates/secrets) | Guarded pages via libsodium: `mlock`, guard pages, and `mprotect` set to no-access except during a scoped borrow — a hardware-enforced version of what `with_secret` does by convention. Needs libsodium and `std`. |
| [`memsec`](https://crates.io/crates/memsec) | The same primitives without the libsodium dependency. |
| [`region`](https://crates.io/crates/region) | Thin safe wrappers over lock/protect for ranges you already own — the page caveats above are yours to handle. |

**And locking is not the whole answer even when done right.** It does not cover
hibernation, which writes all of RAM to disk by design, nor a core dump when the process
crashes. Encrypted swap and disabled core dumps are deployment-level controls that cover
what locking cannot.

Nothing here is a `secure-gate` feature and nothing is planned. Every guarantee this crate
makes is about preventing a *programmer* mistake, mostly at compile time; keeping the
operating system from paging memory is a different layer with a different actor, and
absorbing it would cost `no_std` support, the single-dependency property, and
`#![forbid(unsafe_code)]` to ship a weaker version of the crates above.

## Inherent Rust Limitations

These four limitations are inherent to systems languages with a stack, a
growable heap, an OS that pages memory, and a type system in which reading a
value can copy it. They are **not unique to `secure-gate`** — `secrecy`,
`zeroize`-wrapped collections, C/C++ secret crates, and Go's `memguard` all
share the same threat model. The crate documents them honestly rather than
overclaiming.

The first three are about residue the machine leaves behind. The fourth is a
copy your own code makes, and it is the only one that happens inside the API
this crate provides for safe access.

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
- For long-lived secrets, prefer [`Dynamic<T>`](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html) built with `new_with(len, |slot| …)` or a decode constructor — the buffer is heap-only and never passes through a stack temporary. (`Dynamic::new(v)` still moves `v` in by value.)
- For address-stability needs (FFI, self-referential structs), users may pin the wrapper at the call site: `let key = core::pin::pin!(Fixed::<[u8; N]>::new_with(|a| …));`. This is opt-in; the crate does not impose pinning by default because it would break idiomatic use (returning, storing).

### 2. Heap-reallocation residue (`Dynamic<Vec<T>>` / `Dynamic<String>`)

When a `Vec<T>` or `String` changes capacity, the standard library may
allocate a new buffer, memcpy the contents, and free the old buffer
**without zeroing**. `ZeroizeOnDrop` only zeros the *currently held*
allocation. The abandoned bytes remain readable in heap memory until the
allocator reuses or unmaps the page; they survive into core dumps and swap.

**"May" is load-bearing: whether a buffer is abandoned depends on the allocator
and on heap layout at that moment.** `Vec` asks for a `realloc`, and an allocator
that can extend the chunk where it already sits does so — nothing is copied and
nothing is abandoned. Measured with the default system allocator and no
instrumentation: growing a full 1008-byte buffer by 96, a full 1040-byte `String`
by 16, and a 4096-byte buffer by 65536 all extended **in place**, as did a growth
with one allocated neighbour immediately behind. On a fragmented heap the same
growth **moved**, and the abandoned chunk then held the secret. So this is a real
exposure with a probabilistic trigger, not a certainty, and a threat model should
assume the move. Two consequences worth stating plainly: the byte counts in this
document and in `tests/lifecycle_trace_heap.rs` come from an instrument that does
not override `realloc`, which forces the copying path on every growth — that is
deliberate, because the worst case is the one worth measuring, but it is the worst
case rather than the typical one. And no amount of in-place luck is a mitigation
you can rely on, because you do not control the heap's shape.

**The exposure is bounded, and the bound is worth knowing.** The buffer the wrapper
holds *after* the change is the currently-held allocation, so it is zeroized on
drop, spare capacity included. Measured: after a growth, the replacement block was
released with 0 non-zero bytes of 2016, with a positive control confirming its tail
held payload going in. What is exposed is the set of *abandoned* buffers — plural,
one per move, so a secret grown twice can leave two.

**Shrinking abandons a buffer too, which makes "grows past its capacity" the wrong
mental model.** `shrink_to_fit` and `shrink_to` reallocate downward and free the
old block with the secret still in it, and the truncate-then-shrink case is the
worst of the family: measured on a pre-sized 4096-byte buffer truncated to 2048 and
then shrunk, the abandoned block was released holding **4096** non-zero bytes — the
live prefix *and* the discarded tail — while the wrapper went on to protect only the
smaller replacement. A buffer that never grew at all can leak its whole contents
this way. `reserve` is the converse surprise: it writes no payload and still
abandons the old buffer, so a check keyed on "bytes added" would miss it. The
property that matters is **capacity-changing**, not growing.

**What the crate now handles, and what it cannot.** Where `secure-gate` owns the
growth it wipes the outgoing buffer: `std::io::Write` on `Dynamic<Vec<u8>>`
allocates the larger buffer, copies, zeroizes the old one (contents *and* spare
capacity), and only then releases it. This is verified by an allocator-level
regression test (`tests/heap_zeroize.rs`,
`check_write_growth_orphan_zeroed`) that inspects the freed page at the moment
of growth rather than only at drop.

**Two things to know before relying on that path.** It needs the `std` feature, and
`full` does **not** enable `std` (`full = ["alloc", "rand", "encoding", "ct-eq",
"cloneable", "serde"]`), so a consumer who builds with `--features full` does not have
this impl at all and has no safe growth path. Enable `std` explicitly if you want it.

And it is the impl **on the wrapper** that is safe, not `Write` in general. Reaching
through the wrapper first defeats it: `d.expose_secret_mut().write_all(b"…")` resolves
to the standard library's `impl Write for Vec<u8>`, which grows by `extend_from_slice`
and abandons the old buffer unwiped. Measured on a 1000-byte secret, `d.write_all(…)`
leaves 0 surviving bytes and `d.expose_secret_mut().write_all(…)` leaves 1000. The two
lines look alike and differ completely, so prefer the wrapper's own `Write`.

It cannot do the same for `with_secret_mut` / `expose_secret_mut`: those hand the
caller a `&mut Vec<T>` or `&mut String`, and any capacity-changing operation on it
reallocates entirely outside this crate. **That case remains a real limitation**
(#133), and the patterns below are the mitigation. The same `&mut` is reachable
through `as_wrapper_mut` on a newtype declared with `derive: [IntoWrapper]` or
`[WrapperAccess]`, so the limitation is not confined to the two tier methods named
above.

**The `new_with` closure used to belong on that list and no longer does.** Through
0.9.0-rc.11, `Dynamic::<Vec<u8>>::new_with` handed the closure a **zero-capacity
`Vec<u8>`**, so filling it reallocated, and every reallocation freed the old block
unwiped — inside a constructor whose entire purpose was to avoid an unprotected copy.
Since 0.9.0-rc.12 the signature carries the length: `new_with(len, |slot: &mut [u8]| …)`
allocates the payload buffer once, at exactly `len`, every byte zero, capacity equal to
length — so the wrapper holds no slack and no growth is needed to reach the final size.
The construction costs **two** allocations, not one: that `len`-byte buffer, and the
`Box<Vec<u8>>` header (24 bytes on 64-bit) that `from_protected_bytes` allocates so the
filled buffer can be handed to the wrapper by pointer rather than copied into it. The
crate's instrumented trace (`tests/lifecycle_trace_heap.rs`) counts the allocations of
the constructors built on this path and asserts exactly two, because the count is the
observable that separates filling the protected buffer from filling a scratch buffer and
copying it — a third allocation would *be* that second copy. For residue the load-bearing
half of the count is the first: one payload buffer, sized once, never resized.

**No reallocation *of the slot* is expressible — the closure's own temporaries are still
yours.** `push`, `reserve` and `shrink_to_fit` are not spellable on a `&mut [u8]`, so the
constructor cannot abandon a buffer the way the old empty-`Vec` shape did. That is a
guarantee about the slot and about nothing else. The closure body is ordinary code and may
allocate and grow whatever it likes, and the natural migration walks straight into it:
`new_with(|v| v.extend_from_slice(&material))` becomes `new_with(len, |slot|
slot.copy_from_slice(&material))`, and `material` is usually a `Vec` the caller
concatenates in that same closure — every growth of *it* abandons an unwiped block holding
the secret, which is the defect this release is about, at the same call site it was always
at. Assemble a multi-part fill with
[`SlotWriter`](https://docs.rs/secure-gate/latest/secure_gate/struct.SlotWriter.html)
rather than with a staging buffer: `push_slice` appends each part straight into the slot,
so the parts are never concatenated anywhere else and there is no intermediate buffer to
grow.

This is the one member of the family closed by making the hazard **inexpressible** rather
than by documenting it; what the tier methods hand out is still a growable container, which
is why they stay on the list and the closure does not. "Inexpressible" scopes to the slot,
though — not to everything the closure touches.

**Recommended patterns:**

- For **known-size key material**, prefer [`Fixed<[u8; N]>`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html) (no allocation) or `Dynamic<[u8; N]>` (heap-only, fixed size — no realloc surface).
- For **bounded-size variable-length secrets**, pre-size with `Vec::with_capacity(MAX)` / `String::with_capacity(MAX)` *before* wrapping in `Dynamic`, then only perform capacity-stable mutations through `with_secret_mut`.
- For **infrequent updates**, replace the entire wrapper rather than mutating in place: `dyn_secret = Dynamic::<Vec<u8>>::new_with(len, |slot| …)` — the old `Dynamic` zeroizes its buffer on drop, and the replacement is filled in a slot of exactly `len` zeroed bytes that cannot grow. **The pre-sizing this used to require is now the signature's job.** The guidance here was "call `v.reserve_exact(len)` first", because `new_with` started the closure with an empty `Vec` and a fill that pushed its way up abandoned its own intermediate buffers: measured at 1016 secret bytes across 7 abandoned blocks for a 1008-byte secret. That measurement is the reason the constructor changed rather than advice you still have to follow — the closure now receives `&mut [u8]`, on which `reserve_exact` does not exist and neither does any other capacity change, so the count is 0 by construction rather than by remembering. Use `try_new_with(len, |slot| …)` when the fill can fail; it zeroizes the partial write before returning the error.

  For a **`Dynamic<String>`** there is no constructor to reach for: `Dynamic::<String>::new_with` was removed in 0.9.0-rc.12 with no replacement, because no sized slot is possible for text — a `String` must hold valid UTF-8 and characters have variable byte widths, so a fixed byte window is not somewhere arbitrary text can be written. Build the replacement yourself: `String::with_capacity(len)`, filled once, then `dyn_secret = Dynamic::new(s)`, which **moves** that allocation in, so the buffer you filled is the buffer the wrapper wipes. `From<&str>` is the convenient spelling and the leaky one — it **copies**, and your source string stays where it was, unwiped and out of this crate's reach. Note what is missing next to the `Vec<u8>` arm: nothing in `Dynamic::new`'s signature enforces the pre-sizing. A `String` you grew into by pushing is accepted exactly like one you sized correctly, and by the time you wrap it the buffers that growth abandoned are already on the heap. The `String` hazard is unchanged by this release; only the `Vec<u8>` one was closed.
- For **construction in general**, the length decides the shape, and **under `std`** the two cases cover everything: length known before the fill → `Dynamic::<Vec<u8>>::new_with(len, |slot| …)`; length not known → `Dynamic::new(Vec::new())` plus the `std`-gated `io::Write` impl, which grows by hand and zeroizes each abandoned buffer before releasing it. Neither leaves an unwiped copy behind, and under `std` there is no third case that needs one.

  **Without `std` the second case does not exist.** As the note above on that impl spells out, `full` does not enable `std`, and neither does `default = ["alloc"]` — so the default build and the batteries-included build both land here, and alloc-without-std is the ordinary configuration rather than an exotic one. For such a consumer, a secret whose length is not known before the fill has **no** non-leaking construction path in this crate: growing the `Vec` through `with_secret_mut` abandons unwiped buffers inside the wrapper, and growing one outside and moving it in with `Dynamic::new` abandons the same buffers outside it — `new` protects the allocation it is handed and says nothing about the ones you discarded getting there. Two ways out, both of which have to be chosen deliberately: enable `std` and write through the wrapper's `Write` impl; or find a bound on the length — a protocol maximum, a fixed field width, the size of the frame you are reading — and use `new_with(bound, |slot| …)`, carrying the real length yourself, since the unused tail is zeros the wrapper still considers part of the secret.

  [`SlotWriter`](https://docs.rs/secure-gate/latest/secure_gate/struct.SlotWriter.html) restores the append shape on top of a slot (`push_slice` / `push_byte`, panicking on overrun) so that a multi-part fill is not hand-written offset arithmetic — a fixed slot trades the reallocation hazard for an offset one, and in wire-format code a wrong offset derives the wrong key and still runs.
- For **deployment-level remediation**, install a zero-on-deallocate global allocator such as [`zeroizing-alloc`](https://crates.io/crates/zeroizing-alloc) in the final binary, or rely on OS facilities (Linux `init_on_free=1`, hardened allocators). These are process-wide operational choices rather than a per-crate feature.

A custom-allocator-parameterized `Dynamic<T, A>` (analogous to C++'s
`std::vector<T, ZeroingAllocator<T>>`) would resolve this at the type level. This
document used to say that doing so "currently requires nightly Rust
(`allocator_api`)". That is no longer true and is worth stating accurately, because
it changes what the remaining obstacle is. Nightly is needed only for the standard
library's own `Vec<T, A>`; the [`allocator-api2`](https://crates.io/crates/allocator-api2)
shim provides a stable `Allocator` trait and its own `Vec<T, A>`, and it declares
`rust-version = "1.63"`, so it is within reach of both release lines. Verified: a
twenty-line zeroize-on-free allocator parameterizing such a `Vec` compiled and ran
with no nightly features on both rustc 1.70 and current stable, and saw the
abandoned buffer with 1008 of 1008 bytes still live, wiping them before release —
read back inside the allocator after the wipe and before the inner `deallocate`, the
only window where that can be checked, giving 0.

What actually blocks it here is different, and more fundamental than a toolchain
channel. Implementing such an allocator requires `unsafe impl Allocator`, and this
crate is `#![forbid(unsafe_code)]`. It would also add a non-optional dependency to a
crate that has exactly one, and add a type parameter to `Dynamic`, which is an
API-breaking change. `secure-gate` does not do it; users with strict realloc-residue
requirements should adopt the global-allocator approach above, which needs no change
to this crate at all.

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

### 4. Copying the secret out of a reveal borrow

[`with_secret`](https://docs.rs/secure-gate/latest/secure_gate/trait.RevealSecret.html#tymethod.with_secret)
and [`expose_secret`](https://docs.rs/secure-gate/latest/secure_gate/trait.RevealSecret.html#tymethod.expose_secret)
lend you `&T`. They govern **access** — they cannot govern what the body does with the
bytes once it can see them. Any expression that produces an owned value from that borrow
hands you a copy in ordinary memory, and the wrapper will wipe its own buffer without
ever learning about yours.

This is the only limitation in this document that occurs **while the secret is still
held**, inside the method provided for reading it safely. Nothing is extracted, nothing
is named `into_inner`, and the wrapper is still doing its job.

**Start with the form nothing stops.** A method taking `self` by value copies *through*
the borrow rather than moving out of it, so no borrow-checker rule applies and there is
no operator in the source to notice:

```rust,ignore
let escaped = secret.with_secret(|b| b.to_vec());      // Vec<u8> — no `*` anywhere
let escaped = secret.with_secret(|s| s.to_string());   // String  — via Display
let escaped = secret.with_secret(|b| <[u8; 16]>::try_from(b.as_slice()));
```

Any inner type offering such a method is affected — `Vec::to_vec`, `String::to_string`,
`clone`, `to_owned`, `<[u8; N]>::try_from`, a `collect` over the bytes. This form reaches
**every** wrapper, `Fixed` and `Dynamic` alike.

The two deref forms are more obvious and more limited. They require `T: Copy`:

```rust,ignore
let escaped: [u8; 32] = key.with_secret(|p| *p);   // owned array on the stack
let escaped: [u8; 32] = key.with_secret(|&p| p);   // identical, no `*` in the source
```

**The scoping, in the order that matters:**

| Form | Where it applies |
| ---- | ---------------- |
| Copying method (`to_vec`, `clone`, `to_string`, `try_from`) | **Everywhere.** No language rule prevents it. |
| `*p` and the `&p` binding | Only where `T: Copy` — in practice `Fixed<T>` over `Copy` storage. |

Where `T` is not `Copy`, the deref forms are `E0507: cannot move out of ... behind a
shared reference`. That covers `Dynamic<Vec<u8>>` and `Dynamic<String>`, and also
`Fixed<Fixed<T>>` and `Fixed<zeroize::Zeroizing<T>>` — for the opposite reason, since a
type with a destructor cannot implement `Copy` (`E0184`), and a destructor is precisely
what those two exist for. Both halves are pinned by
`tests/compile-fail/with_secret_no_move_out.rs` and `tests/reveal_copy_out.rs`.

**Read that table in full before acting on it.** "The borrow checker protects `Dynamic`"
is true of the deref forms and false of the copying form — and the copying form is both
the one no search can find *and* the one that occurs in practice. A reader who stops at
the immunity retires the audit for the wrapper most likely to hold bulk plaintext.

**Do not reason from the shape of the storage type.**
[`FixedStorage`](https://docs.rs/secure-gate/latest/secure_gate/trait.FixedStorage.html)
covers `[T; N]`, tuples, `Option<T>`, `Wrapping<T>`, `MaybeUninit<T>`, `Zeroizing<T>`,
`Fixed<T>` and the primitives. That list does **not** partition by hazard:
`Fixed<(u64, u64)>`, `Fixed<Option<[u8; 32]>>` and `Fixed<Wrapping<u64>>` deref-leak
exactly like `Fixed<[u8; 16]>`, while `Fixed<Zeroizing<[u8; 32]>>` cannot. Nothing about
membership predicts which. `Copy` is the discriminator, and it is the only one.

**The compiler suggests the leak.** When `E0507` blocks a move it offers this:

```text
help: consider cloning the value if the performance cost is acceptable
-     let key = secret.with_secret(|v| *v);
+     let key = secret.with_secret(|v| v.clone());
```

That advice is correct about types and wrong about secrets: it converts a compile error
into a silent copy. It is a plausible account of how the copying form arrives in code
nobody wrote carelessly.

**No lint detects any of this.** `clippy::all`, `clippy::pedantic`, `clippy::nursery` and
`clippy::restriction` were pointed at code leaking a key in all three forms; the twelve
diagnostics returned were single-char idents, missing `return`, integer suffixes and the
like. `rustc` under `-D warnings` says nothing. Documentation is the only mitigation that
exists for this one.

Worse than silence, in fact. The one place the toolchain does speak about these
expressions, it points the wrong way: the `E0507` suggestion above moves a caller off the
form the compiler blocks and onto the form nothing does. So this is not a gap where no
tool has an opinion — it is a gap where the only opinion available is the wrong one.

**Detection — read the closure bodies; searching is how you choose which ones.**

```sh
grep -rnE 'with_secret(_mut)?\(\|[a-z_]+\|[^)]*\*'   # deref, including inside a call
grep -rnE 'with_secret(_mut)?\(\|&'                  # pattern binding
```

Neither finds the copying form, because it has no syntax to match on. Treat these as a way
of deciding what to read, never as a way of deciding what is clean — a grep offered without
its blind spot converts *"I should audit this"* into *"I ran the check."* Two consequences
worth adopting:

- **Prefer an over-broad pattern.** Thirteen hits you read one by one is a reading list,
  and it finds things. A pattern precise enough to be trusted is a pattern that gets
  trusted.
- **Record coverage, not a verdict.** Write down which spellings you searched and how many
  bodies you read. "Audited, clean" cannot be corrected by someone who later learns the
  rule was scoped wrong; "I checked these four spellings and read fifteen of sixty bodies"
  can — and that is how one of the defects below was eventually found.

The question that finds this hazard is not *"is this value wrapped?"* — it usually is, one
line later. It is **"wrapped where, relative to the closure?"**

**Incidence.** Three consumer crates examined, two carrying live instances:

- In `aescrypt-rs`, three derefs corrected across commits `443371b` and `38c0c74`
  (verified from public source); two carried secret material, one of them the v0 setup
  key — which for a v0 file *is* the master key.
- In `msoffice-crypto`, reported: one live site among 76, where a SHA-1 verifier hash
  escaped its closure as an owned `Vec` **and** reallocated on the next line — see
  limitation 2; the two stack. The file's own comment said the value "gets no more
  exposure than the key."
- In `age-pq`, reported: an audit run deliberately, by someone who had just been told the
  hazard existed, using the pattern `\|[a-z_]+\| ?\*` — which requires the `*` adjacent to
  the parameter and so missed six sites spelled `from(*bytes)`. Reported clean with a count
  of one; the real count was seven, and it stood for hours.

That last figure is the most useful one here. The first two show code failing; it shows
*the check* failing, which is the likelier outcome for a reader who reaches for a grep.

**Recommended patterns:**

- Copy wrapper-to-wrapper, so the bytes never exist outside something that wipes them:
  `src.with_secret(|s| dst.with_secret_mut(|d| d.copy_from_slice(s)))`.
- Build the destination with a sized constructor and fill it in place —
  [`Fixed::new_with`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#method.new_with)
  or `Dynamic::new_with(len, |slot| …)`. This closes limitation 2 at the same site, which
  is what the `msoffice-crypto` fix did: one sized slot removed both the escape and the
  reallocation.
- Do the work *inside* the closure and let only a non-secret out — a `bool` from a
  constant-time comparison, a length, or a wrapper constructed in place.
- Where a boundary genuinely requires an owned plain value (an FFI call, an upstream API
  taking `Box<[u8; 16]>` with no closure form), that is a decision rather than an oversight.
  Record it where the next reader will look, as this crate does for `into_inner`.

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

  Tier 1 is not a different capability from Tier 2. It is the same reference with its
  lifetime nailed to the call site. `&T` is the dangerous shape precisely because, once
  you hold one, the compiler cannot tell a one-line FFI call from a reference stashed in
  a struct field; the closure is the contract that says *this reference dies here*. That
  is why Tier 1 is preferred rather than required — you could write everything with Tier 2.
- **Tier 3 — Owned consumption**: `into_inner` — returns the plain `T`; **protection ends at the call**. Nothing is copied (an inert sentinel is left for the wrapper's `Drop`), but the value you receive is not wiped for you. Audit separately: `grep into_inner`.

- **Streaming I/O (via `as_reader()`)**: `DynamicReader` implements `std::io::Read` by copying secret bytes into caller-provided buffers through `with_secret` internally. The caller owns zeroization of the destination buffer. `std::io::Write` on `Dynamic<Vec<u8>>` flows data **into** the wrapper, so it is not a *read* surface — but writing past capacity used to leave the outgoing buffer unwiped (see [Heap-reallocation residue](#2-heap-reallocation-residue-dynamicvect--dynamicstring)). That path now grows by hand and zeroizes the old allocation before releasing it. Requires the `std` feature.

**Audit note**: Tier 2, Tier 3, and `as_reader` calls do not appear in simple `expose_secret` grep sweeps and must be reviewed independently.

## Where accident-prevention ends

The tiers above describe **holding** a secret. They stop at the wrapper boundary, and
the crate makes two different promises on either side of it.

| Obligation | Scope |
| ---------- | ----- |
| Accidents must not compile | While the secret is held in `Fixed`/`Dynamic`. Ends at the named extraction — and see the carve-out below, which is inside that window. |
| Documented behavior must be accurate | Everywhere, forever. |

`into_inner` and `EncodedSecret::into_inner` are the named exits that transfer ownership:
you typed the name, the call site is grep-able, and the wrapper is consumed. `expose_secret`
is a named *borrow* — the wrapper keeps ownership and keeps wiping — but it hands out a
reference the compiler will not confine to one call, so audit it alongside them. Past the
ownership transfer the crate is not trying to follow the bytes; that would mean either
another wrapper or a false claim.

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

**The carve-out: one accident does compile, and it compiles inside the window above.**
`with_secret` lends `&T`, so any expression in the closure body that produces an owned
value copies the secret into ordinary memory while the wrapper still holds it — `*p` where
the inner type is `Copy`, and `to_vec` / `clone` / `to_string` on any inner type at all.
The first row of that table is a design goal the type system delivers for `Deref`, `AsRef`
and extraction; it does not reach inside the closure, and no lint covers the gap. This is
limitation 4 above, and it is the reason that row reads "must not" rather than "cannot".

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
- A zero-sized `Fixed` is a compile error at construction — the guard is raised at
  monomorphization, so it covers generic code too; naming the type without building one
  still compiles. Two limits on when it fires, both measured: a post-monomorphization error
  is raised during codegen, so `cargo check` will not report it; and it fires only for a
  codegen root, and every method the newtype macros generate carries an inline attribute,
  so a *library* whose zero-sized constructions sit behind `#[inline]` or generic code
  builds and tests clean and defers the error to its consumers. Dropping the attribute is
  not a fix: what counts as a codegen root depends on the compiler and the profile, and a
  plain non-generic exported function that fails `cargo build` on 1.85 passes
  `cargo build --release` on the same toolchain. No value of
  such a type can exist at runtime, but do not treat green library CI as proof you have
  none — only instantiating the type in a test or a binary proves that. `Dynamic` has no compile-time equivalent, so check that a
  variable-length secret is non-empty when its length is generic or configuration-driven.
  If an empty one reaches you anyway: it reports `len() == 0`, still prints `[REDACTED]`,
  encodes to `""`, and compares `ct_eq`-equal to any other empty.
- Monitor dependencies for CVEs.
- Treat secrets as radioactive — minimize exposure surface.

## Module-by-Module Security Notes

> Security invariants (no `Deref`/`AsRef`, `Debug` prints `[REDACTED]`, zeroize on drop, opt-in clone/serialize) are documented in full on the [`Fixed`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html) and [`Dynamic`](https://docs.rs/secure-gate/latest/secure_gate/struct.Dynamic.html) rustdoc. This section focuses on weaknesses and mitigations not visible from the API surface.

### Wrappers (`dynamic.rs`, `fixed.rs`)

**Potential weaknesses**

- Long-lived `expose_secret()` references can defeat scoping
- `Dynamic<T>` performs no size check and empty contents are a runtime fact; `Fixed`
  rejects a zero-sized inner value at construction.
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

  **Why this is not solved with `unsafe`.** What a `ManuallyDrop` would save is not
  secret bytes; it is one ~24-byte `Box` holding an empty `Vec`/`String`. The secret's
  own heap buffer moves by pointer either way. Meanwhile `into_inner` is exactly where
  `unsafe` is easiest to get subtly wrong — skip the `Drop` and you wipe the caller's
  value, or double-drop the box — and it is the single method that ends protection, so
  an auditor would have to trust a safety comment on the crate's most security-relevant
  line. `#![forbid(unsafe_code)]` is doing real work here. If the allocation ever
  measures, the safe shape is `Option<Box<T>>` plus `take()`: still one pointer thanks
  to the niche, a no-op `Drop` on `None`, at the cost of an `unwrap` in every
  `with_secret`. Do not reach for it without a measurement.
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
- **`Dynamic<Vec<T>>` / `Dynamic<String>` mutation that changes capacity can leave
  the *previous* heap buffer unzeroized.** `Dynamic<T>` zeroizes the *currently
  held* allocation on drop (including `Vec` / `String` spare capacity), so the
  buffer it holds after the change is protected; what is at risk is the buffer it
  stopped holding. Any capacity-changing operation reached through
  `with_secret_mut`, `expose_secret_mut`, or `as_wrapper_mut` can cause `Vec` /
  `String` to allocate a new buffer, copy the data, and free the
  old one through the standard allocator — *without zeroizing the old buffer
  first*. Growing is the obvious case (`push`, `push_str`, `extend`, `insert`,
  `resize`, `splice`, `append`, `write!`), but **`reserve` alone does it while
  writing no payload at all, and `shrink_to_fit` / `shrink_to` do it while the
  buffer only ever got smaller** — the shrink case abandons the discarded tail
  along with the live prefix. Whether any given operation actually abandons a
  buffer depends on whether the allocator can resize the chunk in place, which
  depends on heap layout; assume it cannot. The abandoned bytes remain readable in
  the heap until the allocator reuses or unmaps the page, and they survive into
  core dumps and swap.

  A `new_with` closure was on that list through 0.9.0-rc.11 and is not on it now:
  the closure receives a fixed `&mut [u8]` slot rather than a `Vec`, and none of
  the operations named above is spellable on a slice. What remains listed is what
  hands out a growable container — including any container the closure itself
  builds. A `Vec` assembled inside the closure and then copied into the slot
  abandons its own buffers exactly as before; `SlotWriter` exists so that a
  multi-part fill needs no such container (see
  [Heap-reallocation residue](#2-heap-reallocation-residue-dynamicvect--dynamicstring)).

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
  - replace the wrapper with a fresh `Dynamic::<Vec<u8>>::new_with(len, |slot| …)`
    rather than mutating in place — the old `Dynamic` zeroizes its buffer on drop,
    and the replacement is written into a slot of exactly `len` bytes, every one of
    them zero. No pre-sizing call is needed, or possible: the closure holds
    `&mut [u8]`, which has no capacity to change. This bullet used to say "pre-size
    inside the closure (`v.reserve_exact(len)`)", because `new_with` began with an
    empty `Vec` and a fill that grew it abandoned 1016 secret bytes across 7 blocks
    for a 1008-byte secret; that measurement is why the length moved into the
    signature. `try_new_with(len, |slot| …)` is the same constructor for a fill that
    can fail, and wipes the partial write on `Err`. If the length is not known
    before the fill, `Dynamic::new(Vec::new())` plus the `io::Write` impl is the
    path that wipes every buffer it abandons — but that impl needs `std`, which
    `full` does not enable, so an `alloc`-only build has no safe path for the
    unknown-length case at all and must either add the feature or bound the length
    and use `new_with(bound, …)`.

    **For `Dynamic<String>` the replacement is hand-built.** There is no
    `Dynamic::<String>::new_with` to call — it was removed in 0.9.0-rc.12, because a
    `String` must hold valid UTF-8 and characters have variable byte widths, so no
    fixed byte slot can be handed out for text. Write
    `String::with_capacity(len)`, fill it once, and move it in with
    `Dynamic::new(s)`, which transfers that allocation rather than copying it;
    `From<&str>` **copies** and leaves the source string behind unwiped. Unlike the
    `Vec<u8>` arm, nothing in the signature enforces the pre-sizing here: `new`
    accepts a `String` you grew into just as readily as one you sized, and the
    buffers that growth abandoned are already unwiped on the heap before `new` sees
    anything. This is why `Dynamic<String>` stays on the list above while the
    `Vec<u8>` closure came off it — 0.9.0-rc.12 changed nothing about the `String`
    hazard, and `with_secret_mut` still hands out a growable `String` in the arm
    most likely to hold a password.

  This is a fundamental limitation of `Vec<T>` / `String` in Rust — the
  standard library exposes no allocator hook to zeroize-on-realloc. The same
  limitation applies to `secrecy`, `zeroize`-wrapped collections, and every
  other secret wrapper around the standard collections; a custom-allocator
  workaround exists but trades off significant complexity and is not enabled
  by default in this crate.

  **`Fixed<T>` is exempt, and is now held to it by the compiler.** That sentence
  used to be a claim about the shape people were expected to use rather than
  something the type system checked. `Fixed<T>` was bounded only by `Zeroize`, so
  `Fixed<Vec<u8>>` and `Fixed<String>` compiled, `Fixed<[Vec<u8>; 2]>` hid a growable
  container inside the very array shape this document called exempt, and
  `fixed_newtype!(pub Name, generic Vec<u8>)` was a documented path straight to all
  of it. Measured, each abandoned an unwiped buffer holding the whole secret on any
  capacity change — the same weakness as `Dynamic`, and worse, because
  `Dynamic<Vec<u8>>` has the safe-growth `io::Write` path above and `Fixed<Vec<u8>>`
  has none. `Fixed::new` now requires
  [`FixedStorage`](https://docs.rs/secure-gate/latest/secure_gate/trait.FixedStorage.html)
  on the inner type, so every one of those is a `cargo check` error, and for the macro
  forms the error lands on the declaration.

  Two limits to be precise about. The marker is an **assertion, not an
  enforcement**: like `CloneableSecret`, the compiler checks that you wrote the impl,
  not that it is true, so a type with a `Vec` field that implements `FixedStorage`
  anyway will compile and will leak. What the bound buys is that the claim is written
  at a greppable line in the crate making it. And the bound is on `Fixed`, so it says
  nothing about `dynamic_newtype!`. That macro handles its own case: `generic Vec<u8>`
  and `generic String` are now a compile error at the declaration, because each is the
  same growable payload as the shaped arm with strictly less API — for `Vec<u8>`, no
  `io::Write`, which is the only growth path that wipes the buffer it abandons. Write
  `Vec<u8>` or `String` literally and the safe surface comes with it.

  That reject matches literal tokens, so it is a spelling guard rather than a type-level
  one. `type MyBytes = Vec<u8>` and path-qualified spellings such as
  `alloc::vec::Vec<u8>` are different token sequences and still reach the reduced arm
  with the growable payload and no safe growth path — treat those the way this section
  treats `with_secret_mut`. The macro cannot see through an alias or a path, and a token
  deny-list does not become type-level by getting longer.

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
- **For constructing secrets:** there are three ways in, and what separates them is how
  many copies of the secret exist once you are done (spelled below for
  `Dynamic<Vec<u8>>`; `Fixed<[u8; N]>` has the same three shapes with the length in
  the type — `new_with`, `From<[u8; N]>`, and a copying `TryFrom<&[u8]>`):

  | Constructor | What becomes of the bytes |
  | ----------- | ------------------------- |
  | `new_with(len, …)` — **recommended** | You write into the wrapper's own storage. No other copy is ever created. |
  | `new(owned)` | **Moves** the buffer in: the allocation you filled becomes the one the wrapper protects and wipes. Only as safe as how you built the value. |
  | `From<&str>` / `From<&[u8]>` | **Copies.** Your source buffer stays where it was, unwiped, and this crate cannot reach it. |

  For `Fixed` the ordering is the same: `Fixed::<[u8; N]>::new_with(|arr| { … })` over
  `Fixed::new(value)` when constructing from computed data inline. For
  `Dynamic<Vec<u8>>` the recommended form is `new_with(len, |slot| { … })`, whose slot
  is exactly `len` bytes with every byte zero — the zero tail is a documented guarantee,
  not a side effect, because callers use it as real input (a 40-bit RC4 key is five
  derived bytes followed by eleven zeros, and the key schedule consumes those zeros).
  Reach for [`SlotWriter`](https://docs.rs/secure-gate/latest/secure_gate/struct.SlotWriter.html)
  when the fill has several parts: it appends into the slot and panics on overrun,
  rather than leaving you to get `slot[7..7 + id.len()]` right by hand.

  **`Dynamic::<String>::new_with` was removed in 0.9.0-rc.12 and has no replacement.**
  No sized slot is possible for text: a `String` must hold valid UTF-8 and characters
  have variable byte widths, so a fixed byte window is not somewhere arbitrary text can
  be written. Build a pre-sized `String` yourself — `String::with_capacity(len)`, filled
  once — and hand it to `Dynamic::new`, which **moves** that buffer in rather than
  copying it, so the allocation you filled is the allocation the wrapper wipes.
  `From<&str>` is the convenient spelling and the leaky one: it copies, and your
  original bytes are left behind.

  `Dynamic<T>` remains the strictest option: its buffer lives only on the heap. That is
  a property of the buffer, not of every value that ever reaches it — `Dynamic::new(v)`
  and `From<T>` take `v` by value, and `into_inner` returns it by value, so those three
  do put the secret on the stack briefly. The `new_with` and decode constructors
  (`from_protected_bytes` + `mem::swap`) are the paths with no stack step at all.
- **When the fill can fail**, which covers every secret read from a file, socket or
  device: use `Fixed::<[u8; N]>::try_new_with(|arr| ...)` or, since 0.9.0-rc.12,
  `Dynamic::<Vec<u8>>::try_new_with(len, |slot| ...)`, whose closures return
  `Result<(), E>`. Reading into a plain `[u8; N]` or `Vec<u8>` and then wrapping it is
  the shape to avoid — it copies twice and abandons the first copy unwiped, and no
  amount of care afterwards recovers those bytes. On `Err`, `try_new_with` zeroizes
  whatever the closure wrote before returning, which matters more than it sounds:
  decoders that write into a caller-supplied buffer routinely leave real plaintext in
  it when they fail, so wrapping only on success would leave that partial secret
  unprotected on every malformed input. `E` is yours — the method neither inspects nor
  wraps it, so a consumer's own error type returns straight out of the closure and
  `r.read_exact(slot)` is a complete fill. Do not hand-roll the older workaround of
  capturing an error out of a `new_with` closure and checking it afterwards: it is
  correct only if the check is never forgotten.

**Security-first construction and access patterns**

Just as `with_secret` / `with_secret_mut` are the recommended scoped methods for *accessing*
secrets — keeping the exposed reference tightly bound to the closure lifetime —
`Fixed::new_with` is the recommended constructor for *building* `Fixed` secrets when
minimizing stack residue matters. It writes secret material **directly** into the wrapper's
own storage, eliminating the intermediate stack temporary that can exist with the ergonomic
`new(value)` constructor.

`Dynamic<T>` is already heap-only (`from_protected_bytes` + `mem::swap`), so if stack
residue is the concern it remains the strictest overall choice whichever constructor
you use.

This document used to continue that thought by saying `Dynamic`'s `new_with` variants
"exist purely for API symmetry — not because `Dynamic` carries any stack-residue risk".
That sentence was true about the stack and silent about the heap, which is where
`Dynamic` actually keeps its secret, and the silence did damage: a constructor
documented as existing only for symmetry is one nobody audits and nobody reaches for
on purpose. The old empty-`Vec` shape abandoned 1016 secret bytes across 7 blocks for
a 1008-byte secret, a real consumer shipped that, and it survived review. The sized
slot is not symmetry. It is the only way to get secret material into a
`Dynamic<Vec<u8>>` such that exactly one copy of it ever exists: `new(v)` protects the
allocation you hand it but says nothing about how you filled it, and `From<&[u8]>`
copies and leaves the source behind. Removing the growth from the closure removes the
decision from the caller.

For high-assurance construction, prefer:

- `Fixed::<[u8; N]>::new_with(|arr| { … })` over `Fixed::new(value)`
- `Dynamic::<Vec<u8>>::new_with(len, |slot| { … })` over `Dynamic::new(v)`, and either
  over `From<&[u8]>` — the first creates no second copy, the second moves the copy you
  made, the third leaves it behind unwiped
- when the length is not known until the fill is done:
  `Dynamic::new(Vec::new())` plus the `std`-gated `io::Write` impl on
  `Dynamic<Vec<u8>>`, which zeroizes every buffer it abandons on the way up

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

**`.to_string()` / `.to_owned()` on an `EncodedSecret` are the quiet ones.** They are
deliberately *not* in the token list above, because they are ordinary `str` methods, reached
through `EncodedSecret`'s `Deref<Target = str>` rather than through anything this crate
defines, and a project-wide grep for them is nearly all noise. They are reachable that way on
`EncodedSecret` **only**: `Fixed` and `Dynamic` have no `Deref`, so there the same copy has to
be written `expose_secret().to_string()`, which already trips a listed token. They still produce an untracked plain
`String` (see "Where accident-prevention ends"), so sweep them at the call sites the list
above already found: for every `to_hex` / `to_base32` / `to_base64url` / `try_to_bech32*`
hit, check what happens to the returned `EncodedSecret`. `into_inner` on it is a move and
is already listed; `.to_string()` / `.to_owned()` copy and leave a second live plaintext.

`.to_string()` and `.to_owned()` are the common spellings, not the only ones. Once you hold
the `&str`, **any** use of it that produces an owned `String` is the same event —
`String::from(&*enc)`, `let s: String = (&*enc).into()`, `format!("{}", &*enc)`, pushing it
onto another `String`. Judge the deref site, not the method name: `&*enc` reaching anything
that keeps the bytes is a copy the crate no longer tracks. (`format!("{}", enc)` without the
deref does not compile — `EncodedSecret` has no `Display` — which is the point of that
omission.)
Rationale for keeping `Deref`, and why this residual is accepted rather than closed:
`docs/design/encoded_secret_deref.md`.

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
