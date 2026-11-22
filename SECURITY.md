# Security Considerations for secure-gate

## A guardrail, not a vault

secure-gate stops the ordinary mistakes: a secret printed by `{:?}`, compared with `==`,
left in freed memory, or handed out as a plain `Vec`. It cannot stop someone who decides
to copy a secret out; a secret nobody can read is useless. So the rule is:

- **The easy path is safe.** The obvious way to hold, decode, encode or compare a secret
  keeps it wrapped, wiped and redacted.
- **Reaching it is named.** Every way to the secret, from the scoped `with_secret` to the
  exits (`expose_secret`, `into_inner`, `into_zeroizing`, `as_reader`), is a call you can
  grep for and a reviewer can see.

If the friction feels like it is in your way, that is the library working. Don't route
around it with `.to_vec()`, `*bytes` or `.to_string()`; name the exit instead, or keep the
secret wrapped.

This is also the test for any proposed change. A finding is a defect when the easy path
leaks or an exit has no name. A way out that is already named, or a copy made inside a
`with_secret` closure, is the design working.

## TL;DR

- **No independent audit.** Review the source before production use.
- **No unsafe code.** `#![forbid(unsafe_code)]` in this crate. The `sealed` pre-key's page
  protection lives in the separate `guarded-block` crate, which does use `unsafe` for its
  operating-system calls (mapping, guard pages, locking) and is outside this claim. Audit it
  with the `sealed` feature.
- **Explicit access.** `Fixed` and `Dynamic` have no `Deref` or `AsRef`. Reading goes
  through `with_secret` (scoped, preferred) or `expose_secret` (an escape hatch).
- **Wiped on drop.** The whole allocation, including `Vec` / `String` spare capacity.
- **Redacted `Debug`.** Every wrapper and `EncodedSecret` print `[REDACTED]`.
- **Timing-safe equality.** `.ct_eq()` with the `ct-eq` feature. `==` is not implemented.
- **Opt-in risk.** Cloning and serializing need the `CloneableSecret` /
  `SerializableSecret` marker traits.
- **Protection ends at a named exit.** See the next section; it is the most important one
  in this document.

## Where accident-prevention ends

This crate protects the buffers it owns and stops at a line you can point to.

**The rule.** If this crate allocates a buffer and the caller never holds it, the crate
wipes it on every path: success, error and unwind. If the caller or another library holds
a buffer, the crate does not follow it. It names the exit, documents the copy, and stops.

| Inside: wiped by this crate | Outside: yours, or another library's |
| --- | --- |
| The storage of every `Fixed`, `Dynamic`, generated newtype and `EncodedSecret` | Anything returned by `into_inner` or `EncodedSecret::into_inner` |
| Spare capacity of a held `Vec` / `String` | Copies made through `expose_secret`, or inside a `with_secret` closure |
| Staging buffers of the `try_from_*` decoders, on rejection too | The input you pass to a decoder or a `From<&[u8]>` / `From<&str>` conversion |
| The partial write of a failed `try_new_with` | Buffers a `Vec` / `String` abandoned when *you* changed its capacity (§2) |
| Buffers the wrapper's own `io::Write` outgrows | Buffers a serde deserializer fills before it hands a byte or a string over (its scratch buffer, its input) |
| The buffer a secret is deserialized into, from its first byte: each one it outgrows, and the whole of it on rejection | What serde `Serialize` and `as_reader` write into |
| `sealed` plaintext temporaries and the pre-key | The stack, registers, swap and core dumps (§1, §3) |

Two reasons for a hard line. The left column is a finite list, and each entry has a test
that fails if the wipe stops (`tests/heap_zeroize.rs`, `tests/asm_dse_check.rs`, and
`guarded-block`'s own tests for the pre-key). Nothing in the right column can be tested
from here, and protecting one more layer always looks reasonable, so without the line the
crate would end up claiming what it cannot prove.

For a buffer that seems to sit on the line, ask whether the crate could own it without new
API or `unsafe`. If it can, it is inside. If it cannot, it is documented and left alone.

The two obligations on either side of the line:

| Obligation | Scope |
| --- | --- |
| Accidents must not compile | While the secret is held in a wrapper. Ends at the named exit. One carve-out, below. |
| Documented behavior must be accurate | Everywhere, always. |

**Named exits.** `into_inner` and `EncodedSecret::into_inner` transfer ownership of a plain
value: not wiped, not redacted. `expose_secret` is a named *borrow*: the wrapper keeps
wiping, but the reference is not confined to one call, so audit it with the exits.
`EncodedSecret::into_zeroizing()` returns `zeroize::Zeroizing<String>`: still wiped on
drop, and its `Debug` is opaque (`zeroize` ≥ 1.9.1, which this crate requires), but it
derefs to `String`. It exists for APIs that demand that type by name. This crate does not
re-export `zeroize`.

```rust,ignore
let plain = key.into_inner();         // [u8; 32]: plain, not wiped, not redacted
let enc = other_key.to_hex();         // EncodedSecret: wiped on drop, Debug redacted
let s: String = enc.to_string();      // via Deref<Target = str>: untracked
```

**Redaction is a property of the wrapper, not of the value.** `format!("{:?}", key)` prints
`[REDACTED]`; `format!("{:?}", key.into_inner())` and `format!("{:?}", &*enc)` print the
secret. An encoded secret is the whole secret in another alphabet.

**The carve-out: one accident does compile.** `with_secret` lends `&T`, so an expression in
the closure that produces an owned value copies the secret into ordinary memory while the
wrapper still holds it. No lint covers it. This is
[limitation 4](#4-copying-the-secret-out-of-a-reveal-borrow), and it is why the first
obligation reads "must not" and not "cannot".

## What secure-gate does NOT protect against

- **A process that can be read.** Debugger, `/proc/<pid>/mem`, code running in the process.
- **Swap, page files, hibernation, core dumps.** Use operating-system controls; see below
  and [§3](#3-swap--core-dumps--external-memory-exposure).
- **`panic = "abort"`, SIGKILL, hard crashes.** `Drop` does not run, so nothing is wiped.
  Keep the default `panic = "unwind"` in security-sensitive builds.
- **`static` secrets.** Rust never drops a `static`. `Fixed::new` is `const fn`, so
  `static KEY: Fixed<[u8; 32]> = Fixed::new([...])` compiles and is never wiped.
- **Everything in the right column above.** Copies the caller makes, values past a named
  exit, serializer output.
- **Side channels other than equality timing.** Cache, power, EM, branch prediction.
- **Lossy hardware readout of RAM** (cold boot, Rowhammer, Spectre-class) for `Fixed` and
  `Dynamic`, which hold plaintext. The opt-in `sealed` feature narrows this; see §3.
- **Allocation-based denial of service in deserialization.** `MAX_DESERIALIZE_BYTES`
  bounds what this crate holds: a byte sequence is refused at the first byte past it. It
  does not bound what the deserializer or the transport has already read into memory.
- **Stack and register residue.** Temporaries, FFI boundaries, compiler spills (§1).

### If swap residue is in your threat model

The answer is `mlock` (POSIX) / `VirtualLock` (Windows), and the obvious way to apply it is
wrong in a way nothing reports.

**Locks are page-granular and `munlock` is not reference-counted.** A lock covers the whole
page containing the address, and one unlock releases it however many locks preceded it. So
`region::lock(&my_secret, size)` on a heap secret locks a page it shares with other
secrets, and dropping any one of them unlocks all the rest, silently. On a `Fixed` it locks
a page of unrelated stack frames, and a move leaves the lock behind.

**Locking correctly means owning the allocation:** one secret per page-aligned region. That
is a different data structure from `Box<T>`, so `Fixed` and `Dynamic` do not offer it. The
crates that do:

| Crate | What it buys |
|---|---|
| [`secrets`](https://crates.io/crates/secrets) | Guarded pages via libsodium: `mlock`, guard pages, no-access outside a scoped borrow. Needs libsodium and `std`. |
| [`memsec`](https://crates.io/crates/memsec) | The same primitives without libsodium, as `unsafe fn`s. |
| [`guarded-block`](https://crates.io/crates/guarded-block) | From this repository; what the `sealed` pre-key uses. A fixed-size block in its own mapping between guard pages, read-only once filled, locked, `MADV_DONTDUMP` on Linux. A safe API; write-once. |
| [`region`](https://crates.io/crates/region) | Thin wrappers over lock/protect for ranges you already own. The page caveats are yours. |

Locking does not cover hibernation or a crash dump. Encrypted swap and disabled core dumps
are deployment controls that cover what locking cannot.

## 3-Tier Access Model

- **Tier 1, scoped borrow (preferred):** `with_secret` / `with_secret_mut`. The borrow ends
  when the closure returns. It is the same reference as Tier 2 with its lifetime nailed to
  the call site.
- **Tier 2, direct reference (escape hatch):** `expose_secret` / `expose_secret_mut`. For
  FFI and third-party APIs that need `&T` / `&mut T`.
- **Tier 3, owned consumption:** `into_inner`. Returns the plain `T`; protection ends at
  the call. Nothing is copied (an inert sentinel is left for the wrapper's `Drop`).
- **Streaming (`std`):** `as_reader()` copies secret bytes into buffers the caller owns and
  must wipe. `io::Write` on `Dynamic<Vec<u8>>` flows data *into* the wrapper and wipes each
  buffer it outgrows.

### Audit surfaces

Every way a secret is read, moved, encoded or decoded is an explicit call. Search for:

```
expose_secret  expose_secret_mut  with_secret  with_secret_mut
into_inner  into_zeroizing  as_reader
from_wrapper  as_wrapper  as_wrapper_mut  into_wrapper
with_role  with_role_mut  unseal
SecretLen  byte_len
to_hex  to_hex_upper  to_base32  to_base64url
try_to_bech32  try_to_bech32m  try_to_bech32_sized  try_to_bech32m_sized
try_from_hex  try_from_base32  try_from_base64url  try_from_bech32  try_from_bech32m
```

The second and third rows are the newtype and `sealed` surfaces: `from_wrapper` and its
siblings are where a value enters or leaves a role, `with_role` / `with_role_mut` open a
sealed role, and `unseal` ends sealing. `SecretLen` is the import that marks code measuring
a secret, the sealed types included: since 0.10.0 `SealedFixed`, `SealedDynamic` and the
sealed role types are measured through it too.

Also audit every `CloneableSecret`, `SerializableSecret` and `FixedStorage` impl; each is
an assertion the compiler does not check.

`.to_string()` / `.to_owned()` on an `EncodedSecret` are not in the list: they are `str`
methods reached through its `Deref`, and a project-wide grep for them is noise. Check them
at the call sites the encoder names already found: for every `to_hex` and its siblings,
look at what happens to the returned value. Any use of `&*enc` that keeps the bytes
(`String::from`, `format!("{}", &*enc)`, a `json!` field) is a copy the crate no longer
tracks. `format!("{}", enc)` does not compile, because `EncodedSecret` has no `Display`.
Why `Deref` is kept: `docs/design/encoded_secret_deref.md`.

**`EncodedSecret`'s `Deref<Target = str>` is a handoff point on purpose. Do not remove it
as a fix.** It is the one exception to "no `Deref`" in this crate, and the exception is the
design. A caller who calls `to_hex` and its siblings has asked for the encoded text, to
pass to an API that takes `&str` (a driver, `serde_json`, a header). `EncodedSecret` wipes
the copy the crate made and redacts `Debug`; what the caller does with the `&str` it hands
out is past the boundary rule above, like a copy made inside `with_secret`. Removing `Deref`
would break every such call site and close no confidentiality gap: the bytes are reachable
either way, through any accessor that replaced it (an `as_str()`, say; there is none
today). Changing it is a design decision for
the maintainer, not a cleanup.

## Inherent Rust Limitations

Four limitations follow from a stack, a growable heap, an operating system that pages
memory, and a type system in which reading a value can copy it. `secrecy`,
`zeroize`-wrapped collections and C/C++ secret libraries share them. The first three are
residue the machine leaves; the fourth is a copy your own code makes.

### 1. Stack-move residue (`Fixed<T>`)

Moving a `Fixed<T>` (returning it, passing it by value, storing it in a field) copies the
bytes and leaves the old stack slot as it was until something overwrites it. Zeroize-on-drop
wipes only the current location.

- Build with [`Fixed::new_with`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#method.new_with),
  which writes straight into the wrapper; `from_random` does too. A decoder writes into a
  wiped staging buffer and copies out of it into the wrapper. `Fixed::new(v)` takes a value
  that already existed somewhere.
- Pass `&Fixed<T>` / `&mut Fixed<T>`, not `Fixed<T>` by value.
- For a long-lived secret prefer `Dynamic` built with `new_with(len, …)` or a decoder: the
  buffer is heap-only and has one address. For a fixed-size key that is `Dynamic<[u8]>`:
  `Dynamic<[u8; N]>` has no `new_with`, so building one means `Dynamic::new` of an array,
  which passes it over the stack and leaves the source unwiped, or of a `Box`, which moves
  only the box but the box had to be filled first.
  `Dynamic::new(v)` and `into_inner` pass the value over the stack once.
- For address stability, pin at the call site: `core::pin::pin!(Fixed::new_with(…))`.

### 2. Heap-reallocation residue (`Dynamic<Vec<T>>` / `Dynamic<String>`)

When a `Vec` or `String` changes capacity, the standard library may allocate a new buffer,
copy, and free the old one without zeroing it. The wrapper wipes the buffer it holds at
drop, spare capacity included. It cannot wipe a buffer the collection already gave back.

**What triggers it.** Any capacity change reached through `with_secret_mut`,
`expose_secret_mut` or `as_wrapper_mut`: `push`, `extend`, `insert`, `resize`, `write!`,
and also `reserve` (writes nothing, still moves) and `shrink_to_fit` / `shrink_to`. The
property is *capacity-changing*, not *growing*.

**How bad.** Measured:

| Case | Left in freed memory |
| --- | --- |
| 4 KiB secret grown one byte, forced to move (x86-64 Linux/glibc and Windows) | 4032 of 4032 payload bytes |
| 4096-byte buffer truncated to 2048, then `shrink_to_fit` | all 4096 bytes, the discarded tail included |
| 1000-byte secret, `d.expose_secret_mut().write_all(…)` | 1000 bytes |
| Same, through the wrapper: `d.write_all(…)` | 0 bytes |

Whether a given change moves the buffer depends on the allocator and heap layout: the
system allocator often extends in place, and a fragmented heap moves. Assume it moves. A
secret grown twice can leave two copies.

**What the crate closes.**

- `Dynamic::<Vec<u8>>::new_with(len, |slot: &mut [u8]| …)` hands out a slot of exactly
  `len` zeroed bytes. Growth is not expressible on a slice. (Through 0.9.0-rc.11 the
  closure got an empty `Vec`, and filling it left 1016 secret bytes in 7 freed blocks for a
  1008-byte secret; that is why the length moved into the signature in rc.12.) The zero
  tail is a guarantee callers may use as input. `tests/lifecycle_trace_heap.rs` pins the
  constructor at two allocations: the payload and the `Box<Vec<u8>>` header.
- `try_new_with(len, …)` is the same for a fill that can fail, and wipes the partial write
  on `Err` and on panic. Reading into a plain buffer and wrapping it afterwards copies
  twice and leaves the first copy unwiped.
- [`SlotWriter`](https://docs.rs/secure-gate/latest/secure_gate/struct.SlotWriter.html)
  appends parts into a slot, so a multi-part fill needs no staging `Vec`. The slot cannot
  grow, but a `Vec` you build *inside* the closure still can, and still leaks.
- `io::Write` on `Dynamic<Vec<u8>>` (`std`) grows by hand and wipes each old buffer. Use
  the impl on the wrapper: `d.expose_secret_mut().write_all(…)` is the standard library's
  `Vec` impl and leaks. Note `full` does not enable `std`.
- `Fixed<T>` cannot hold a growable type. `Fixed::new` requires
  [`FixedStorage`](https://docs.rs/secure-gate/latest/secure_gate/trait.FixedStorage.html),
  so `Fixed<Vec<u8>>` is a compile error. The marker is an assertion: implement it for a
  type with a `Vec` field and it compiles and leaks.
- `dynamic_newtype!(…, generic Vec<u8>)` and `generic String` are rejected, because the
  generic arm has no safe growth path. The reject matches tokens, so `type B = Vec<u8>` or
  `alloc::vec::Vec<u8>` still gets through.

**What it cannot close.** `with_secret_mut` hands out `&mut Vec<T>` / `&mut String`, and
what you do with it happens in the standard library (#133). And **`Dynamic<String>` has no
sized constructor**: text is variable-width UTF-8, so no fixed byte slot fits it, and
`Dynamic::<String>::new_with` was removed in rc.12. Build a `String::with_capacity(len)`,
fill it once, and move it in with `Dynamic::new(s)`. Nothing enforces the pre-sizing.

**Choosing a construction path.**

| You have | Use | Copies left behind |
| --- | --- | --- |
| Known-size key material | `Fixed::<[u8; N]>::new_with`, `from_random` or a decoder | None from building it; returning or passing the `Fixed` by value can leave a stack copy (§1) |
| Known-size key material, heap only | `Dynamic::<[u8]>::new_with(N, …)`, `from_random(N)` or a decoder | None |
| Bytes, length known before the fill | `Dynamic::<Vec<u8>>::new_with(len, …)` / `try_new_with` | None |
| Bytes, length unknown, `std` on | `Dynamic::new(Vec::new())` + the wrapper's `io::Write` | None |
| Bytes, length unknown, no `std` | Bound the length and use `new_with(bound, …)`, carrying the real length yourself | None. There is no other safe path. |
| An owned buffer you built | `Dynamic::new(owned)`: moves it in | Whatever building it left |
| A borrowed `&[u8]` / `&str` | `From`: copies | Your source stays, unwiped |
| A secret to change later | Replace the wrapper, or pre-size and make only capacity-stable edits | None |

**Deployment-level fix.** A zero-on-free global allocator in the final binary removes this
whole hazard. Only an application can install one; `#[global_allocator]` may appear once
per program, so a library must not.

```toml
zeroizing-alloc = "0.1.1"
```

```rust
use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
```

- Put it in `src/lib.rs` if the crate has a library target, so integration tests get it
  too; otherwise in `src/main.rs`.
- Check any such allocator before trusting it. Its wipe sits just before a free, which the
  optimizer may delete as a dead store, silently. A wipe behind a function pointer is
  defeated by PGO with LTO. Prefer volatile stores or an inline-assembly barrier, and ask
  for a demonstration under PGO and LTO. For `zeroizing-alloc` 0.1.1 that demonstration is
  `tools/pgo_allocator_compare.sh`, with a captured run in `docs/design/receipts/`. Pin
  `0.1.1`: `0.1.0` lacks the barrier.
- Alternatives: Linux `init_on_free=1`, hardened allocators.

A `Dynamic<T, A>` with a zeroizing allocator parameter would fix this in the type. It no
longer needs nightly ([`allocator-api2`](https://crates.io/crates/allocator-api2) declares
1.63; verified on 1.70 and stable). It is not done because it needs `unsafe impl
Allocator`, a second mandatory dependency, and a breaking type parameter.

### 3. Swap / core dumps / external memory exposure

Process memory can be paged to disk or written to a core dump. Once written, wiping in the
process is irrelevant. The stack is included: a `Fixed` can leave earlier copies there
(§1), so for a long-held secret prefer `Dynamic` or a sealed type.

**Deployment controls.** Encrypted swap. Core dumps disabled (`prctl(PR_SET_DUMPABLE, 0)`,
`RLIMIT_CORE` 0, `--ulimit core=0`). Hibernation disabled or encrypted. `mlock`, with the
caveats [above](#if-swap-residue-is-in-your-threat-model). `Fixed` and `Dynamic` never call
`mlock` or set process flags.

**Opt-in, beside these: the `sealed` feature.** `SealedFixed<N>` and `SealedDynamic` (and
the role types `sealed_fixed_newtype!` and `sealed_dynamic_newtype!` build on them) hold a
secret as ChaCha20-Poly1305 ciphertext and open it for one `with_secret` /
`with_secret_mut` / `with_role` call. The sealing key, `SHA-256(salt ‖ pre-key)`, is recomputed on every
access and never stored. The salt is 32 random bytes from the system RNG, drawn afresh for
every seal, including every re-seal after `with_secret_mut` / `with_role_mut`. The AEAD
nonce is all-zero, on purpose: a fresh salt means a fresh key, so no key ever encrypts
twice and a nonce has nothing to separate. A sealed value is never re-encrypted under its
old salt, and sealed types have no `Clone`, so no two encryptions share a key. A random
nonce is not missing; a code path that encrypts again without drawing a fresh salt would be
the bug.

The pre-key is 16 KiB of random bytes in a `Prekey` that each
sealed object holds an `Arc` to. Since rc.15 it lives in a mapping of its own between two
no-access guard pages, read-only once filled (`guarded-block`, which uses `unsafe` for
those operating-system calls; this crate's no-`unsafe` rule does not cover it). When the last reference
drops it is wiped, unlocked and unmapped.

The cipher leaves a copy of the key on the stack, so every seal and open ends by
overwriting the stack below the call, on a panic too: 32 KiB, and for a `SealedFixed<N>`,
whose plaintext and its moves sit on the stack, about 3·N in a release build and 10·N in a
debug build once that is more. (A fixed 32 KiB, before 0.10.0, left the key or plaintext
behind for keys above about 16 KiB.) A probe found the key 4
times there before the overwrite in a debug build and a plaintext copy once in a release
build; after it, neither. That was measured on x86_64 Windows (rustc 1.98.1) and x86_64
Linux (rustc 1.87.0; with the overwrite removed the probe found the key there too, and with
it, nothing), in `docs/design/receipts/sealed-stack-residue/`. A monthly CI run repeats it on
x86_64 Linux and Windows, macOS ARM64 and Linux ARM64, each time first with the overwrite
removed, to show the probe can see the key on that target, then as shipped. Its first run
(rustc 1.100.0, `runs_ci.txt`) found nothing as shipped on any of the four. A run that
cannot see the key with the overwrite removed fails the job.

**Linux ARM64 release builds cannot be measured.** There the release build leaves no key
copy the probe can reach even with the overwrite removed, so a clean result would show
nothing. The monthly run probes only the debug build on Linux ARM64, which is in reach. Nor
are 32-bit targets probed.

One count the monthly run does not gate: the plaintext copy that `SealedFixed::unseal` can
leave. `unseal` returns an ordinary `Fixed` by value, and a by-value return can leave a
stack copy in the caller's frames, out of the overwrite's reach (the `unseal` row below,
and §1). The probe found that copy once in a Windows release build (rustc 1.98.1,
`runs_panic.txt`) and not in the first monthly run.

| Threat | Sealed |
|---|---|
| Lossy readout (cold boot, Rowhammer, Spectre-class) | Narrowed: one wrong bit of the pre-key's 131,072 makes the key useless |
| Sealed secret paged to **swap** | Covered when the pre-key is locked |
| Pre-key lock refused (quota) | `Prekey::lock_status()` returns `Err`; nothing panics, but the pre-key can then be swapped |
| **Hibernation** file | Not covered: it captures locked pages too |
| Linear **over-read** from another buffer (C code, Heartbleed-style) | Covered for the pre-key: it is off the heap, and a read running into it faults on a guard page (measured) |
| **Core dump** (Linux) | Pre-key is `MADV_DONTDUMP`. The flag was checked; no dump was taken |
| **Crash dump** (Windows, macOS) | Not covered with `Prekey::new()`. On Windows, `Prekey::new_idle_noaccess()` keeps an idle pre-key out of a dump (measured) but cannot also keep it locked |
| Clean read of process memory | Not covered |
| The plaintext temporary while the closure runs, and copies the closure makes | Not covered. The temporary is wiped, and the stack below overwritten, when the call returns |
| Registers, and stack beyond the overwritten region | Not covered |
| The `Fixed` that `SealedFixed::unseal` returns | An ordinary `Fixed`: returning it can leave a stack copy (§1). Read through `with_secret` / `with_role` instead |
| A sealed value after it is **dropped** | Its ciphertext, salt and tag are wiped where it was dropped, so nothing is left to open even while other sealed values keep the pre-key alive. Not covered: stack slots a `SealedFixed` was moved out of, which keep ciphertext (§1) |
| The **length** of a sealed secret | Readable through `SecretLen`, whose import marks the call (see Audit surfaces). `Debug` does not print it |
| Growing a sealed `String` / `Vec<u8>` | Not expressible. `with_secret_mut` hands out `&mut str` / `&mut [u8]`, and `sealed_dynamic_newtype!` has no `with_role_mut`, so nothing can reallocate the plaintext (§2). To change the length, `unseal`, edit and seal again |

**Lock quotas.** On Windows every `VirtualLock` draws on the working-set quota: about
eleven pre-keys lock by default (Windows 11), and `SetProcessWorkingSetSize` raises it. On
Unix the limit is `RLIMIT_MEMLOCK`; where it is 0 (common in containers) every lock is
refused, `lock_status()` says so, and sealing still works.

**Cost.** About 7–11 µs per access for a 32-byte key, and about 32 KiB of free stack; for a
`SealedFixed<N>` above about 10 KiB, about 3·N (10·N in a debug build).
Design and numbers: `docs/design/sealed_memory.md`. Everything the sealed types
deliberately do not implement, each with its reason, is listed in the `sealed` module's
rustdoc under "Not implemented, on purpose".

### 4. Copying the secret out of a reveal borrow

`with_secret` and `expose_secret` lend `&T`. They govern access, not what the body does
with the bytes. Any expression that produces an owned value copies the secret into ordinary
memory, and the wrapper wipes its own buffer without knowing about yours. This is the only
limitation here that happens while the secret is still held, inside the method meant for
reading it safely.

```rust,ignore
// Copying methods: work on every wrapper, and nothing stops them.
let escaped = secret.with_secret(|b| b.to_vec());
let escaped = secret.with_secret(|s| s.to_string());

// The copy can be made for you, by whatever takes the reference.
let encoded = key.to_base64url();                    // EncodedSecret: protected
let body = serde_json::json!({ "key": &*encoded });  // Value::String: owned, unwiped

// Deref forms: only where the inner type is `Copy`.
let escaped: [u8; 32] = key.with_secret(|p| *p);
let escaped: [u8; 32] = key.with_secret(|&p| p);
```

| Form | Where it applies |
| ---- | ---------------- |
| Copying method (`to_vec`, `clone`, `to_string`, `try_from`, `collect`) or a callee that stores the bytes | **Everywhere.** No language rule prevents it. |
| `*p` and the `&p` binding | Only where `T: Copy`, in practice `Fixed` over `Copy` storage. Elsewhere it is `E0507`. |

`Copy` is the only discriminator. `Fixed<(u64, u64)>` and `Fixed<Option<[u8; 32]>>` leak by
deref like `Fixed<[u8; 16]>`; `Fixed<Zeroizing<[u8; 32]>>` cannot. "The borrow checker
protects `Dynamic`" is true of the deref forms and false of the copying form, which is the
one that occurs in practice. Both halves are pinned by
`tests/compile-fail/with_secret_no_move_out.rs` and `tests/reveal_copy_out.rs`.

**The toolchain does not help.** No clippy group (`all`, `pedantic`, `nursery`,
`restriction`) flags any of these. Worse, when `E0507` blocks `|v| *v`, rustc suggests
`v.clone()`, which turns a compile error into a silent copy.

**Detection.** Read the closure bodies; search only to choose which.

```sh
grep -rnE 'with_secret(_mut)?\(\|[a-z_]+\|[^)]*\*'   # deref, including inside a call
grep -rnE 'with_secret(_mut)?\(\|&'                  # pattern binding
```

Neither finds the copying form or a copying callee. Prefer an over-broad pattern you then
read, and record coverage ("these spellings, fifteen of sixty bodies"), not a verdict. Of
three consumer crates examined, two had live instances, and in the third an audit using a
too-narrow pattern reported one site where there were seven.

**Instead:**

- Copy wrapper to wrapper: `src.with_secret(|s| dst.with_secret_mut(|d| d.copy_from_slice(s)))`.
- Build the destination in place with `Fixed::new_with` or `Dynamic::new_with(len, …)`.
- Do the work inside the closure and return only a non-secret: a `bool`, a length, a
  wrapper built in place.
- Where a boundary truly needs an owned plain value, that is a decision. Record it where
  the next reader will look.

## Encoding and decoding

**One protected output type.** Every encoder returns `EncodedSecret`: a `Zeroizing<String>`
with redacted `Debug` and no `Display`. There is no unprotected encoder.

| Method | Returns | Wiped on drop? |
|---|---|---|
| `to_hex()`, `to_hex_upper()`, `to_base32()`, `to_base64url()` | `EncodedSecret` | Yes |
| `try_to_bech32()`, `try_to_bech32m()`, and their `_sized::<N>` forms | `Result<EncodedSecret, _>` | Yes |
| `EncodedSecret::into_zeroizing()` | `Zeroizing<String>` | Yes; derefs to `String` |
| `EncodedSecret::into_inner()` | `String` | **No. Protection ends here** |

**Encoding an encoded secret is a compile error.** Encoders need `AsRef<[u8]> +
EncodableBytes`, and `str` is not `EncodableBytes`, so `encoded.to_hex()` and
`"text".to_hex()` are rejected. Write `.as_bytes()` if the UTF-8 is what you mean.

**Decoders.** Use the format-specific constructors (`try_from_hex` and siblings on `Fixed`
and `Dynamic`); the bytes are decoded into a staging `Zeroizing` buffer and never sit
anywhere unwiped. `Dynamic<Vec<u8>>` takes that buffer over without a copy. `Fixed` and
`Dynamic<[u8]>` copy the bytes out of it into the wrapper (for `Dynamic<[u8]>`, a box of
exactly their length), and the staging buffer is wiped.

- The decode buffer is allocated inside `Zeroizing` before the backend writes to it, so it
  is wiped on success, on rejection and on unwind (#96, #97). Through 0.9.0-rc.17 the hex,
  Base32 and Base64url paths wiped on success only: a valid encoding followed by junk, such
  as a hex key with a CRLF line ending, was rejected with the decoded secret left in a
  freed block.
- `Fixed` decoders without `alloc` decode into a `Zeroizing<[u8; N]>` on the stack.
- Bech32 decoders validate the checksum and HRP before any payload byte exists. Prefer the
  HRP-checked forms over `_unchecked`, to prevent cross-protocol confusion (BIP-173 vs
  BIP-350). HRP comparison is not constant-time; the HRP is public.
- Base32 accepts only RFC 4648 §6 uppercase, unpadded input. Decoding is **not injective**:
  unused trailing bits are ignored, so `"MZ"` and `"MY"` decode alike. Never treat a
  successful decode as proof two strings were equal.
- Treat all decoder input as untrusted. The parsers are fuzzed in CI.

**Bech32 code length.** `try_to_bech32` / `try_from_bech32` use `BECH32_CODE_LENGTH`
(1023), within which the checksum is guaranteed to detect up to four character errors. The
`_sized::<N>` forms take the bound as a parameter. `N` above 1023 forfeits that guarantee;
the checksum is still computed and verified. Size `N` with
`bech32_code_length(hrp_len, payload_bytes)`.

**Errors.** Error enums are identical in debug and release builds. They may carry numeric
lengths (`InvalidLength { expected, got }`), never input-derived text or bytes. All are
heap-free, `Copy` and `#[non_exhaustive]`. If length metadata is sensitive in your
deployment, redact at the logging boundary.

## Feature Security Implications

| Feature | Security impact | Recommendation |
| --- | --- | --- |
| `alloc` *(default)* | `Dynamic<T>` and wiping of `Vec` / `String` spare capacity. Without it the crate is `#![no_std]` with no heap, checked in CI on `thumbv7em-none-eabihf`. | Enable unless the target has no heap |
| `std` | Adds `as_reader()` (copies into caller-owned buffers) and the wiping `io::Write` on `Dynamic<Vec<u8>>`. Not part of `full`. | Enable when you need unknown-length construction (§2) |
| `ct-eq` | `.ct_eq()` via `subtle` | Strongly recommended |
| `rand` | `from_random()` uses the system RNG and panics on failure. A caller-supplied RNG needs no feature: `try_new_with(\|b\| rng.try_fill_bytes(b))`, which wipes on `Err`. | Use `try_new_with` where RNG failure should be handled |
| `serde-deserialize` | The secret is read into a buffer this crate wipes, from its first byte: no plain `Vec<u8>` or `String` exists in between, and each buffer a byte sequence outgrows is wiped before it is freed (0.9.1, #249; through 0.9.0 a 1008-byte `Dynamic<Vec<u8>>` from a JSON array left 5 freed blocks holding 992 bytes). Rejected input is wiped too. `Fixed<[u8; N]>` pre-sizes and rejects over-length input before growing. **Stops at the deserializer:** what it buffers before handing a byte or a string over is its own, and for text that includes `serde_json`'s scratch buffer when the string has escapes. 1 MiB default limit (`MAX_DESERIALIZE_BYTES`, or `deserialize_with_limit`), checked as bytes arrive. | Trusted sources; cap size at the transport. Where the deserializer's own residue matters, fill a `new_with` slot instead |
| `serde-serialize` | Writes the full secret into buffers this crate cannot reach. Opt-in per type via `SerializableSecret`. | Enable sparingly; audit every impl |
| `encoding`, `encoding-*` | Constant-time hex, Base32 and Base64url via RustCrypto backends; bech32 via `bech32`. Encoders need `alloc`; `Fixed::try_from_*` does not. | Enable per format |
| `cloneable` | Opt-in cloning via `CloneableSecret`. Each clone is a wrapper and wipes itself. | Use minimally |
| `sealed` | See §3. `SealedFixed`, `SealedDynamic`, `sealed_fixed_newtype!`, `sealed_dynamic_newtype!`. Implies `std` and `rand`; adds `chacha20poly1305`, `sha2`, `guarded-block`, and `poly1305` and `ctutils` only to turn on a feature and set a version floor. Every dependency holding key, keystream, MAC or hash state has its `zeroize` feature on. | For long-held keys |
| `full` | Everything except `std` and `sealed` | Convenient; audit what you use |

## Other notes

- **Zero-sized `Fixed` is a compile error**, raised at monomorphization, so it covers
  generic code. Two limits: `cargo check` does not report it, and it fires only for a
  codegen root, so a library whose zero-sized constructions sit behind `#[inline]` or
  generics can build clean and defer the error to its consumers. Instantiate the type in a
  test to be sure. `Dynamic` has no equivalent: check a variable-length secret is non-empty
  when its length is configuration-driven. An empty one reports `len() == 0`, prints
  `[REDACTED]`, encodes to `""`, and is `ct_eq`-equal to any other empty.
- **`Dynamic::into_inner` allocates a 24-byte sentinel `Box`.** If that allocation panics,
  the wrapper still holds the secret and wipes it on unwind. It is not replaced with
  `ManuallyDrop` and `unsafe`: that would save no secret bytes and put `unsafe` on the one
  method that ends protection. `Fixed::into_inner` allocates nothing.
- **`into_inner` returns the plain value.** Earlier releases returned an `InnerSecret<T>`
  that kept wiping; it is gone. To keep protection, keep the wrapper, or move the value
  into `zeroize::Zeroizing` yourself.
- **Errors can reveal length.** A wrong decoded length is reported. Length is usually
  public (key sizes); redact where it is not.
- **Cost.** A `Fixed` is the size of its contents; a `Dynamic` is a `Box` of them, with
  the allocation that implies. Neither adds work at run time beyond the wipe on drop.
  `sealed` costs more per access (§3).

## Audit Status

`secure-gate` has **not** undergone an independent security audit.

The crate is small. `zeroize` is the only unconditional dependency; with default features
`cargo tree` is two lines. Every other dependency arrives with the feature that names it:
`subtle` (`ct-eq`), `rand` (`rand`), `base16ct`, `base32ct`, `base64ct`,
`bech32` (encoding), `serde`, and `chacha20poly1305` + `sha2` + `guarded-block` (`sealed`,
which also lists `poly1305` and `ctutils` directly, only to turn on `poly1305`'s `zeroize`
feature and to set `ctutils`' version floor).
No proc-macro crate is pulled in unless you enable `serde`.

Before production use, review the source, the dependency versions, and these tests:

- `tests/heap_zeroize.rs`: an allocator that checks freed heap blocks are zero. Covers the
  crate-owned heap buffers in the table near the top.
- `tests/asm_dse_check.rs`: reads the release assembly to confirm the optimizer kept the
  wipe for `Fixed` and newtypes.
- `tests/zeroize_tests.rs`, `tests/lifecycle_trace_heap.rs`, `tests/lifecycle_trace_handoff.rs`:
  drop order, spare capacity, allocation counts, hand-off at `into_inner`.
- `tests/heap_residue*.rs`: the §2 hazard measured, with and without a wiping allocator.
- `tests/ct_eq_tests.rs`, `tests/proptest_suite/`: constant-time equality.
- `tests/compile-fail/`: the accidents that must not compile.
- `tools/check_sealed_zeroize.sh` (run on every pull request): fails if a `sealed` dependency that
  holds key, keystream, MAC or hash state is built without its own `zeroize` feature.

## Vulnerability Reporting

- **How**: GitHub private vulnerability reporting (Repository → Security → Report a
  vulnerability). Do not open a public issue or pull request for a vulnerability.
- **Expected response**: Acknowledgment within 48 hours; coordinated disclosure
- **Public disclosure**: After a fix is released and users have had reasonable time to update

## Supported Versions

| Line | Security fixes |
|---|---|
| The latest minor release on `main` (0.10.x once 0.10.0 ships; 0.9.x until then) | Yes |
| 0.8.x (`release/0.8`, for Rust older than 1.87) | Yes, as 0.8.x patch releases |
| Earlier minor lines on `main` (0.9.x after 0.10.0 ships) | No: upgrade to the latest minor |
| Release candidates | No |

## Past Advisory

**0.5.0 through 0.7.0-rc.14 did not zeroize on drop** (0.7.0-rc.15 was tagged but never
published). The docs said secrets were wiped on drop, but those versions had no
`impl Drop`, only the empty `ZeroizeOnDrop` marker, so nothing was wiped. Versions 0.1.0
to 0.4.3 did wipe on drop, through `secrecy::SecretBox` and `zeroize::Zeroizing`; the flaw
starts at 0.5.0 (2025-11-22). The first published fix is 0.8.0-rc.1 (2026-03-22); the
0.8.0-alpha.1 entry in `CHANGELOG-ARCHIVE.md` has the details, with a correction note for
its version range. Every version before 0.8 is yanked from crates.io: 0.5.0 onward for this
flaw, 0.1.0 to 0.4.3 as early, superseded wrappers over `secrecy`. All were yanked on
2026-03-17 UTC except 0.6.0, yanked on 2025-12-08 when 0.6.1 replaced it (crates.io
records each version's last update). Since then the wipe is checked by tests rather than
by reading the code: `tests/heap_zeroize.rs` checks freed heap blocks are zero, and
`tests/asm_dse_check.rs` checks the optimizer keeps the wipe.

## Disclaimer

This document reflects design intent and observed properties as of the current release.

**No warranties are provided.** Users are solely responsible for their own security
evaluation, threat modeling and audit.
