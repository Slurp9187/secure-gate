# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 0.9.0 (the 0.9 release candidates, the 0.8 release candidates and every
earlier version) are in [CHANGELOG-ARCHIVE.md](CHANGELOG-ARCHIVE.md). The 0.8 line, 0.8.0
included, is recorded in the `release/0.8` branch's own changelog.

## [0.10.0] - Unreleased

A breaking release: four changes, each listed below with the code that stops compiling and
what to write instead. Every "before" was checked to fail and every "after" to compile
against this release. Nothing about what is wiped, or when, changes. MSRV stays 1.87.
Once 0.10.0 ships, 0.9.x gets no more fixes (`SECURITY.md`, Supported Versions); 0.8.x
still does.

### Migration

1. **Sealed types are measured through `SecretLen`.** `SealedFixed`, `SealedDynamic`, the
   types `sealed_fixed_newtype!` / `sealed_dynamic_newtype!` generate, and the hidden
   `__private::SealedRole` / `__private::SealedDynRole` those types hold lose their plain
   `len()` and `is_empty()` and implement `SecretLen` instead, which also gives them
   `byte_len()`. `grep SecretLen` now finds code that measures a sealed secret, which it
   did not before.
   - Before: `sealed.len()` with no import. Error: E0599, no method named `len`.
   - After: add `use secure_gate::SecretLen;`. The call itself does not change.
   - Before: `sealed.len()` inside a `const fn`. Error: E0599 as above; once `SecretLen`
     is imported, E0015, a trait method is not const.
   - After: use the length from the type (`N` for `SealedFixed<N>`), as for `Fixed`.
   - Before: a trait of your own with a `len`, `byte_len` or `is_empty` method, implemented
     for a sealed type and called where `SecretLen` is imported. Error: E0034, multiple
     applicable items. (This crate's own sealed fuzz target hit it.)
   - After: rename your method, or call it as `YourTrait::len(&s)`.
2. **`SecretLen` no longer requires `RevealSecret`.** That requirement is what kept the
   sealed types out. An implementation of `SecretLen` written for 0.9 still compiles.
   - Before: `fn f<T: SecretLen>(t: &T) { t.expose_secret(); }`. Error: E0599, no method
     named `expose_secret` found for `&T`.
   - After: name both bounds, `T: SecretLen + RevealSecret`.
3. **`Dynamic<[u8]>` has the constructors, decoders and encoders of `Dynamic<Vec<u8>>`**
   (#267). `new_with`, `try_new_with`, `from_random`, every `try_from_*` decoder and the
   `ToHex`, `ToBase32`, `ToBase64Url`, `ToBech32` and `ToBech32m` impls are now written once,
   generic over the new sealed trait `DynamicBytes` (`Vec<u8>` and `[u8]`). A call that names
   the shape, on the binding, a field, a function argument or with a turbofish, compiles as
   before. A call that names it nowhere has two candidates.
   - Before: `let k = Dynamic::new_with(32, f);` or `let k = Dynamic::try_from_hex(s)?;` with
     nothing later fixing the type. Error: E0283, type annotations needed.
   - After: `let k: Dynamic<Vec<u8>> = ...` or `Dynamic::<Vec<u8>>::new_with(32, f)`.
   - Before: `Dynamic::new(vec).to_hex()`. Error: E0283, type annotations needed.
   - After: `Dynamic::<Vec<u8>>::new(vec).to_hex()`.
4. **The hidden `__with_wrapped` hooks are removed.** `SealedFixed::__with_wrapped`,
   `SealedFixed::__with_wrapped_mut` and `SealedDynamic::__with_wrapped` were the 0.9.0
   hooks behind the sealed macros, hidden and documented as not a public API. 0.9.1 kept
   them unused.
   - Before: `sealed.__with_wrapped(wrap, f)`. Error: E0599, no method named `__with_wrapped`.
   - After: `sealed.with_secret(f)` / `with_secret_mut(f)`, or `with_role` on a sealed role.

### Added

- `Dynamic<[u8]>`: `new_with`, `try_new_with`, `from_random`, the `try_from_*` decoders and
  the encoding traits (#267). Each allocates exactly the length it needs before a byte of
  the secret is written, so a boxed slice no longer has to be built from a `Vec` of the
  right capacity. A decoded slice is copied out of the decoder's staging buffer, which is
  wiped; `tests/heap_zeroize.rs` gates on both blocks, and fails when the staging buffer is
  freed unwiped.
- `DynamicBytes`, the sealed trait behind those methods. It cannot be implemented outside
  this crate and has no methods outside it: the buffer operations it needs are on a
  crate-private supertrait, so outside code can neither implement them nor call them,
  even through a `DynamicBytes` bound.
- `SecretLen` for `SealedFixed<N>`, `SealedDynamic<T>`, the sealed macro types,
  `__private::SealedRole` and `__private::SealedDynRole`.

### Removed

- The plain `len()` / `is_empty()` on `SealedFixed`, `SealedDynamic`, the sealed macro
  types, `__private::SealedRole` and `__private::SealedDynRole` (see Migration 1).
- `SealedFixed::__with_wrapped`, `__with_wrapped_mut` and `SealedDynamic::__with_wrapped`
  (Migration 4).

### Documentation

- A known-size key held on the heap is `Dynamic<[u8]>` built with `new_with`, `from_random`
  or a decoder. `SECURITY.md`, the `Dynamic` docs and the crate docs had recommended
  `Dynamic<[u8; N]>`, which has no such constructor and is built from an array passed by
  value. `SECURITY.md`'s construction table no longer says a `Fixed` leaves no copy: one
  returned or passed by value can (§1). Its "Zero overhead" line now says a `Dynamic` is a
  `Box`.
- The crate docs list four inherent limits, as `SECURITY.md` does, give the sealed cost as
  7–11 µs, and say the encoders on `Dynamic<[u8]>` and the others read the wrapper's own
  bytes. The sealed module docs name every measured target.
- README: a row for reallocation through `with_secret_mut`; sealed needs about 32 KiB of
  stack, and a refused lock fails nothing, so check `lock_status()`; the first example
  says `"…".into()` leaves the literal unwiped. README and `SECURITY.md` name `poly1305`
  and `ctutils`, which `sealed` lists only for a feature and a version floor.

- `SECURITY.md` says `EncodedSecret`'s `Deref<Target = str>` is a deliberate handoff point,
  not a gap to close.
- `SECURITY.md` says how a sealed value's nonce is chosen: all-zero, because every seal
  and re-seal draws a fresh 32-byte salt and so a fresh key.
- The sealed stack overwrite is now measured on x86_64 Linux as well as x86_64 Windows
  (`docs/design/receipts/sealed-stack-residue/runs_linux.txt`). `tools/stack_probe.sh` runs
  it monthly on Linux and Windows x86_64, macOS ARM64 and Linux ARM64
  (`.github/workflows/stack-probe.yml`), outside the merge checks, and fails when a run
  with the scrub removed cannot see the key. Its first run found nothing as shipped on any
  of the four (`runs_ci.txt`). A Linux ARM64 release build leaves no key in the probe's
  reach, so it cannot be measured and only the debug build runs there. 32-bit is not
  probed.
- README says which versions are yanked and why (0.9.0-rc.6 stays listed while a downstream
  user is pinned to it), and that a patch release may restrict an API to fix a security
  bug, with 0.9.1's change to the hidden `__private` role conversions as the example. "Zero-overhead" is dropped from the crate
  description: `Dynamic` boxes its value and the sealed types cost microseconds an access.
- README names `EncodedSecret`'s `Deref` where it says a held secret has none, gives one
  sealed cost figure (7–11 µs, as SECURITY.md), and no longer calls access inside
  `with_secret` "full" protection. Its sealed section names the `Prekey` trade-off:
  `Prekey::new()` stays the default and keeps the pre-key locked against swap;
  `Prekey::new_idle_noaccess()` keeps an idle pre-key out of a Windows user-mode crash dump
  but cannot keep it locked there.
- `SECURITY.md`: vulnerabilities are reported privately only; a supported-versions table;
  a past advisory for the zeroize flaw in 0.5.0 through 0.7.0-rc.14 (rc.15 tagged but never
  published), fixed in 0.8.0-rc.1; `guarded-block` uses `unsafe`
  and is outside the no-`unsafe` claim.
- Releases before 0.9.0 moved to `CHANGELOG-ARCHIVE.md`, linked from the top of this file
  and shipped in the package. Their text is unchanged except one marked correction under
  0.8.0-alpha.1, which named the wrong range of affected versions and yank date.

## [0.9.1] - 2026-11-21

Additions and fixes only: nothing covered by the stability promise is removed or changes
signature. Two things do change for existing code. One `Debug` output (`SlotWriter`,
under Changed). And the hidden role traits in `secure_gate::__private`, which have been marked semver-exempt
since 0.9.0 and are not for direct use, take an extra argument (under Fixed): code that
called them directly, instead of through the macros, stops compiling, which is the point
of the fix. These come from a
consistency review of the 0.9.0 API, which looked for places where the `sealed` types differ from the rest of the
crate without saying so.

### Added
- **Sealed values wipe themselves on drop.** `SealedFixed` and `SealedDynamic`, and so the
  types both sealed macros generate, zero their ciphertext, salt and tag when dropped, and
  are `ZeroizeOnDrop`. The ciphertext is not the secret, but until now a dropped sealed
  value left it in freed memory, where it would still open for anyone able to read it and
  the pre-key while another sealed value kept that pre-key alive. How far it reaches: the
  value where it is dropped. A `SealedDynamic`'s one heap buffer is wiped whole; a
  `SealedFixed` that was moved leaves ciphertext in the stack slots it left, as a moved
  `Fixed` leaves plaintext. Both tests were run with the wipe removed and fail.
- **`secure_gate::scoped::RevealScoped` no longer needs the `sealed` feature.** A library
  can now accept "plain or sealed" secrets by bounding on the trait without pulling in
  `std` and the cipher crates. Still not re-exported at the crate root, for the glob-import
  reason its module docs give.
- `SealedDynamic::<Vec<u8>>::from_random(len, &prekey)`, and `from_random(&prekey)` on
  every `sealed_fixed_newtype!` type, beside the existing `SealedFixed::from_random`. The
  key is generated and sealed without existing as a plain role in between.
  `sealed_dynamic_newtype!` deliberately has none: the macro sees only the role's name,
  not whether it holds a `String`, for which random bytes make no sense.

- **`SecretLen` and serde `Deserialize` for `Dynamic<[u8]>`** (#267), the boxed slice that
  cannot grow. `len()`, `is_empty()` and `byte_len()` work as on `Dynamic<Vec<u8>>`, also
  for `Dynamic<[T]>`. `Deserialize` and `Dynamic::<[u8]>::deserialize_with_limit` read as
  the `Vec<u8>` ones do and finish with one copy into a slice of exactly the secret's
  length. The rest of #267 is **not** here, because it turned out not to be additive: a
  second `Dynamic::new_with` / `from_random` / `try_from_hex` makes
  `let k: Dynamic<Vec<u8>> = Dynamic::from_random(32)` ambiguous, and a second `ToHex` impl
  does the same to `Dynamic::new(vec).to_hex()`. Both stop code that compiles on 0.9.0.
  They wait for a breaking release. Serde `Serialize` was never missing: it needs
  `SerializableSecret` on an inner type you own, as it does for `Dynamic<Vec<u8>>`.

### Changed
- **`SlotWriter`'s `Debug` prints `[REDACTED]`.** It printed
  `SlotWriter { position: 6, remaining: 2, len: 8 }`: never a byte, but `len` is the
  secret's length and `position` how much of it is written, and it was the one `Debug`
  in the crate that showed a secret's length. Code that needs the cursor reads it by name
  through `position()`, `remaining()` and `is_full()`, which are unchanged. Nothing stops
  compiling; a test that compared the old text needs updating.

### Fixed
- **Deserializing a `Dynamic` no longer goes through an unprotected copy** (#249).
  `Dynamic<Vec<u8>>` and `Dynamic<String>` let serde build a plain `Vec<u8>` or `String`
  and wrapped it afterwards. A byte sequence grew that plain `Vec`, and every buffer it
  outgrew was freed with the secret in it: a 1008-byte secret from a JSON array left 5
  freed blocks holding 992 of its bytes. The bytes are now read into a buffer this crate
  wipes from the first one, growth is done by hand (allocate, copy, wipe the old buffer),
  and a secret refused partway, for its length or because the input is malformed, is wiped
  too. Text the deserializer lends is copied once into a buffer of exactly its length;
  text it gives away is taken over. Generated `dynamic_newtype!` types get this through
  the wrapper they hold. What is accepted and what is refused is unchanged: the same
  serde entry points (`deserialize_seq`, `deserialize_string`) and the same message for an
  over-long secret. Two differences in the error. The length is now checked inside the
  deserializer's call instead of after it returns, so a format that tracks position
  (`serde_json`) appends where it was to the message, for bytes and for text alike. And
  an over-long byte sequence is refused at the first byte past the limit instead of
  after it has all been read, so input that is both too long and malformed further on is
  refused as too long, where it used to be refused for the malformed part. For a byte
  sequence the limit therefore bounds what this crate allocates; text the deserializer lends is
  checked before it is copied, and text it gives away is taken over first and then
  checked, so a refused one is wiped.
  **Where it stops:** at the deserializer. What it buffers before handing a
  byte or a string over is its own; for text with escapes, `serde_json`'s scratch buffer
  still grows as a plain `Vec` and is freed unwiped. `tests/heap_zeroize.rs` gates on the
  outgrown, rejected and cut-short buffers; the growth and take-over checks were each run
  with the wipe removed and fail.
- **With the `sealed` feature on, a role could be entered and left without its derive.**
  `fixed_newtype!` and `dynamic_newtype!` promise that a value becomes a role, or stops
  being one, only through `derive: [FromWrapper]` / `[IntoWrapper]`. To let the sealed
  macros move a role without copying its bytes, every byte role and every `String` /
  `Vec<u8>` role also implemented a hidden conversion (`secure_gate::__private::FixedRole`
  / `DynamicRole`), and that conversion was callable:
  `<AppKey as FixedRole>::from_fixed(bare_fixed)` compiled with no derive. It was
  `#[doc(hidden)]` and outside the stability promise, but it was reachable from safe code
  and no audit search finds it. Each conversion now takes a token for its own role that
  only this crate's sealing code can make, and the sealed macros hold a hidden wrapper
  typed by its role, which is built only from that role and gives back only that role.
  Six compile-fail doctests pin each case. The hidden `__with_wrapped` /
  `__with_wrapped_mut` methods on `SealedFixed` and `SealedDynamic` are no longer what the
  macros call. They are hidden and documented as not a public API, but they are `pub`
  methods on exported types, so they stay as they were, with no deprecation warning,
  until the next breaking release removes them.
  What they reach is what `with_secret` and `with_secret_mut` on the same value already
  reach: `__with_wrapped` lends the opened `Fixed` or `Dynamic` for the closure, and
  `__with_wrapped_mut` lets the closure take that `Fixed` out and leave another to be
  re-sealed in its place, as `with_secret_mut` lets it copy the bytes out and overwrite
  them. Neither exists on a type a sealed macro generates.
  - How far it reaches: safe code outside the module that declares the role. `unsafe`
    code can conjure a token, as it can conjure anything. And the macros emit
    `struct Name(Wrapper)` with a private field, which Rust makes visible in the module
    that invokes the macro and in every module nested inside it, at any depth: there,
    `Name(fixed)` and `name.0` compile with no derive, as they always have. Modules
    outside that subtree, and every other crate, are held to the derives. Declare roles in a module of their own to keep that set small. No secret was exposed by this; it weakened a type-level promise.
  - The types the sealed macros generate, and every documented method on them, are
    unchanged. Code that named `secure_gate::__private` directly may stop compiling; that
    module is not public API.

### Documentation
- **The `sealed` length methods are a stated gap.** `SealedFixed`, `SealedDynamic` and the
  types `sealed_fixed_newtype!` and `sealed_dynamic_newtype!` generate have plain `len()`
  and `is_empty()` methods, because `SecretLen` requires `RevealSecret` and a sealed type
  cannot implement that. Those calls need no `use secure_gate::SecretLen;`, so searching
  for the import does not find code that measures a sealed secret. This has been so since
  `sealed` first shipped and was not written down. It now is: on `SecretLen`, on each of
  the methods, in the `sealed` module and in `SECURITY.md`. Fixing it removes methods, so
  it cannot happen in a 0.9.x release.
- The `sealed` module's "Not implemented, on purpose" list is complete. It named three
  omissions; it now names every one, each with its reason: `RevealSecretMut`, `SecretLen`,
  `into_inner`, `Clone`, `PartialEq` / `Eq`, `Zeroize` (they are `ZeroizeOnDrop`), serde, the
  encoders and decoders, `From` / `TryFrom`, `io::Write`, the macros' `derive:` options,
  `with_role_mut` on `sealed_dynamic_newtype!`, and the `from_random` constructors that
  are deliberately absent.
- New "Where the protection stops" section in the `sealed` module (the pre-key, the
  closure, `unseal`), and two rows in `SECURITY.md` §3 on a dropped sealed value and on
  the length of a sealed secret.
- `SECURITY.md` audit search list: adds `from_wrapper`, `as_wrapper`, `into_wrapper`,
  `with_role`, `with_role_mut`, `unseal`, `SecretLen` and `byte_len`.
- `Dynamic::new`: the docs said borrowed input is not accepted. That holds for
  `Dynamic<String>` and `Dynamic<Vec<u8>>`. `Dynamic::<str>::new("...")` and
  `Dynamic::<[u8]>::new(&bytes[..])` compile, copy the bytes and leave the source unwiped;
  the docs now say so.
- README Stability: the `release/0.8` line stays on 0.8.x and never takes a breaking
  change. README Contributing: where tests live.
- `Fixed` module docs: `Serialize` needs `serde-serialize` only. The `fixed_newtype!`
  catch-all error now lists `try_new_with` in the reduced API.
- Broken intra-doc links are reported only when every feature is enabled, which is how
  docs.rs and CI build. A narrower `cargo doc` used to report about a hundred links to
  feature-gated items; it is now clean.

### Tests
- Each inline test module says in one line why it is not in `tests/`. The pre-key `Debug`
  check moved to `tests/sealed.rs`, since it reads nothing private.

## [0.9.0] - 2026-11-14

First stable release of the 0.9 line. From this release the public API follows semantic
versioning as described in the README's Stability section. The API is the same as
0.9.0-rc.19; the changes since then are documentation and tests only.

### Documentation
- `sealed` docs (`Prekey::new_idle_noaccess`, the `sealed` module): the Windows idle
  no-access claim is scoped to what was measured (#289). It makes another process's
  `ReadProcessMemory` fail and keeps the pre-key out of a user-mode full-memory dump
  (`MiniDumpWithFullMemory`) taken while it is idle. It does not stop a process that may
  change this one's page protection (`VirtualProtectEx`) and then read, and a kernel or
  complete memory dump captures physical memory whatever the protection.
- README install lines now use `"0.9"`, and the note on tracking release candidates is gone.

### Tests
- New stateful fuzz target for the `sealed` module, including `from_random`, run in the
  smoke and nightly fuzz jobs (#293).
