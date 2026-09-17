# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0-rc.13] - Unreleased

### Security
- **Said what a zero-on-deallocate allocator has to do, instead of naming one.** All three
  sites that recommended a specific crate now give the property to check. Such an allocator's
  wipe sits immediately before a deallocation, which makes it a dead store the optimizer is
  entitled to delete, and the deletion is silent. An implementation that defends the wipe by
  routing it through a function pointer is defeated by profile-guided optimization with LTO:
  indirect-call promotion turns the indirect call direct, inlining follows, and dead-store
  elimination removes the fill while the pointer load it was hiding behind still executes.
  Volatile stores are safe from that removal because LLVM's language reference forbids it; a
  fill held by an inline-assembly barrier taking the block's own pointer also holds.

  Naming no crate is what lets this text be identical on both lines. Every version that names
  one forces `release/0.8` to answer a question property-based wording never asks, since that
  line pins MSRV 1.70.

- **The hazard is now a number rather than a claim.** A 4 KiB secret grown one byte past its
  capacity through `with_secret_mut`, with an allocated neighbour behind it so the reallocation
  has to move, leaves **4032 of 4032 payload bytes** readable in the abandoned block — x86-64
  Linux/glibc and Windows alike. Taken with no allocator installed, so it measures this crate's
  hazard and not any allocator's behaviour, and it reproduces in about fifteen lines.

  The readout window starts at byte 64 deliberately, and the section says so: a freed glibc
  chunk carries the allocator's free-list links in its first bytes — two words in a small bin,
  four once sorted into a large bin — so sampling below that reads pointers, finds no pattern,
  and looks like proof the hazard is imaginary.

- **`#[global_allocator]` in `src/main.rs` does not reach integration tests.** Each file under
  `tests/` compiles to its own binary linking the library target, so it gets the default
  allocator. A test written to confirm secret handling then runs without the mitigation it was
  written to confirm — a green result about the wrong binary. If your crate has a library
  target, declare the allocator there.
- **Documented a limitation of `with_secret` / `expose_secret`: they govern access, not
  what the closure body does with the bytes.** Any expression producing an owned value
  from the lent `&T` leaves a copy in ordinary memory that the wrapper never learns about
  and therefore never wipes. This is the only limitation in `SECURITY.md` that occurs
  *while the secret is still held*, inside the method provided for reading it safely —
  nothing is extracted, nothing is named `into_inner`, and the code reads as protected.

  Three spellings, and the scoping is the load-bearing part because consumers act on it.
  `*p` and the `&p` binding form need `Inner: Copy`, so the borrow checker rejects them
  for `Dynamic<Vec<u8>>` and `Dynamic<String>` with `E0507` — and, for the opposite
  reason, for `Fixed<Fixed<T>>` and `Fixed<Zeroizing<T>>`, since a type with a destructor
  cannot be `Copy` (`E0184`). **That immunity does not extend to a method that copies**:
  `to_vec`, `clone`, `to_string`, `<[u8; N]>::try_from` copy *through* the borrow rather
  than moving out of it, so no rule applies, and there is no operator in the source to
  notice. The copying form reaches every wrapper, and it is the one that occurs in
  practice.

  Two things the entry says that are worth repeating here. `Copy` is the only
  discriminator — `FixedStorage` covers tuples, `Option`, `Wrapping`, `MaybeUninit`,
  `Zeroizing` and `Fixed` as well as `[T; N]`, and that list contains both hazardous and
  immune members, so reasoning from the shape of the storage type gives the wrong answer
  in both directions. And no lint detects any of it: `clippy::all`, `pedantic`, `nursery`
  and `restriction` were pointed at code leaking a key in all three forms and returned
  twelve diagnostics, every one cosmetic. `rustc` under `-D warnings` says nothing.
  Documentation is the only mitigation that exists.

  The compiler actively suggests the leak: `E0507`'s own help is *"consider cloning the
  value if the performance cost is acceptable"*, which converts the rejected move into a
  silent copy. That is a plausible account of how the copying form arrives in code nobody
  wrote carelessly.

  Found by downstream consumers upgrading to `0.9.0-rc.12`; three crates examined, two
  carrying live instances, one of them a v0 master key. The most useful figure is not a
  defect count but a detection failure: an audit run deliberately, by someone who had just
  been told the hazard existed, with a pattern requiring the `*` adjacent to the closure
  parameter, missed six sites spelled `from(*bytes)` and was reported clean with a count
  of one against a real count of seven. The entry therefore frames its grep patterns as a
  way of deciding what to *read*, never as a way of deciding what is clean, and asks for
  audits to record their coverage rather than their verdict.

### Added
- `tests/compile-fail/with_secret_no_move_out.rs` and `tests/reveal_copy_out.rs`, a pair
  pinning the two halves of that scoping from opposite sides: that moving a secret out of
  a reveal borrow does *not* compile for a non-`Copy` inner type, and that copying one out
  *does*. A test demonstrating a leak looks strange until you notice that the second claim
  is otherwise prose — and prose about what a compiler permits is exactly what rots
  silently. An earlier draft of the guidance said `Dynamic` was immune outright; that was
  wrong in the direction that retires an audit, and these tests exist so the corrected
  version cannot quietly drift back.

### Changed

- Two historical entries carried publication claims with a shelf life, and both had rotted:
  `0.9.0-rc.11`'s *"0.9.0-rc.11 is unpublished"* and `0.9.0-rc.9`'s *"this unpublished
  release"*. Both were true when written and false the day each shipped. Restated so they
  cannot rot again — the reasoning each recorded is preserved, only the tense that made it
  perishable is gone. This is the failure mode the changelog protocol names as the one that
  actually breaks here, and it had reached two sections.

- `SECURITY.md` §4 described the copying form as "a method taking `self` by value" and
  enumerated the methods — `to_vec`, `clone`, `to_string`, `try_from`. Too narrow, and the
  gap was found by a consumer auditing their tree against it: the copy can equally be made
  *for* you by whatever you hand the reference to. `json!({ "k": &*encoded })` stores an
  owned `String` holding the secret, and the call site contains no copying method to
  notice — the same shape reaches `insert`, `push`, a `String` struct field, a `params![]`
  binding, and every `impl Into<String>` parameter. The section now asks what the receiver
  does with the `&str`, not only what you called on the secret, and the detection note
  records that this case carries no token on the secret's side at all.

- `Dynamic::new_with`'s `# Panics` section told callers to bound an attacker-supplied `len`
  before passing it, which is right but assumes the check already existed somewhere. A
  downstream consumer found by building against it that the sized slot does not merely
  *move* their bound — it changes its *shape*. Under a grown `Vec` their ceiling was the
  decompressor's, and an overstated `manifest:size` failed a comparison downstream; under
  the slot that size **is** the allocation length, and `vec![0u8; 9_000_000_000]` does not
  fail a comparison. A caller whose length comes from a trusted source has nothing to do; a
  caller whose length comes from the file format has acquired an allocation-sized surface
  where it previously had a comparison. Said so.
- `RevealSecret::expose_secret` gains a "Coming from `secrecy`" note. The two crates share
  this spelling deliberately — this one kept the vocabulary when it went its own way — but not the
  posture: as of `secrecy` 0.10.3 a plain reference is documented there as "the only method
  providing access to a secret", whereas here it is the auditable escape hatch and
  `with_secret` is the recommended path. The habit transfers silently, because reaching for
  the familiar name compiles, works, and protects the secret exactly as before, so nothing
  signals that the narrower tool exists. Named on `expose_secret` rather than `with_secret`
  because that is where a migrating reader actually lands.
- `SECURITY.md` gains "4. Copying the secret out of a reveal borrow" under **Inherent Rust
  Limitations**, whose preamble now counts four rather than three and distinguishes the
  first three (residue the machine leaves behind) from the fourth (a copy your own code
  makes). The **What secure-gate does NOT protect against** bullet on caller copies now
  says the hazard includes copies made *inside* a `with_secret` closure.
- **Where accident-prevention ends** gains a carve-out. Its table promises that "accidents
  must not compile while the secret is held in `Fixed`/`Dynamic`", and this is an accident
  that compiles inside exactly that window. The promise is real for `Deref`, `AsRef` and
  extraction, and it does not reach inside the closure — which is why the row reads "must
  not" rather than "cannot". Left unqualified it would have been a false claim in the
  document's most load-bearing table.
- `RevealSecret::with_secret` and `expose_secret` gain a note at the point of use. The
  existing sentence "the closure receives a reference that cannot escape" is true of the
  reference and invites the wrong conclusion about the secret, so it is now followed by
  what can escape, and by the wrapper-to-wrapper form to use instead.


- `docs/design/nominal_newtypes.md`: the rc.12 amendment covered half of what rc.12
  invalidated. Trap 4's residue — the generated call it quotes as
  `<Dynamic<String>>::new_with(…)`, and its warning about an `E0034` ambiguity that a later
  forwarder could reintroduce — was left standing, as was §1's `Vec<u8>` list, which is
  stale in the *other* direction: the `new_with` it names now takes a length, and
  `try_new_with` is forwarded beside it and missing from the list entirely. The amendment
  now says so, and notes that the list was an abbreviation before this release too (it
  names neither `from_rng` nor the base32/base64 encoders), so a reader takes it as the
  shape of each arm rather than its full surface. Amended rather than rewritten, per this
  document's own convention for superseded claims.
- `tests/compile-fail/dynamic_newtype_alias_rejected.rs`: its header described the
  pre-`generic`-marker fallthrough as producing "a newtype missing `new_with`,
  `SecretLen`, and the encoders". Two thirds of that is now wrong — `Dynamic<String>` has
  no `new_with` at all since rc.12, and the shaped `String` arm has never had encoders
  (pinned by `dynamic_string_no_hex.rs`), so the generic arm withholds none from it. It
  now reads `SecretLen` and `From<&str>`, matching the macro. The header keeps its exact
  line count so the `.stderr` anchor at line 11 does not move.

  Both corrections were made on `release/0.8` while backporting rc.12 and are re-derived
  here. The staleness was inherited on both lines, not introduced by that backport.

### Removed

- **BREAKING: `derive: [ConstantTimeEq]` is rejected on the shaped newtype arms.** It was
  accepted-and-inert in 0.9.0-rc.11 and 0.9.0-rc.12, both of which are published; this is a
  break against a released surface, not tidying of an unreleased one.

  Constant-time equality became automatic on those arms in rc.11 — `fixed_newtype!`'s
  size-literal arm and `dynamic_newtype!`'s `String` and `Vec<u8>` arms — because the token
  had put the extra word on the spelling this crate recommends as the safer of the two, for
  the one comparison whose alternative is a timing leak. To keep older declarations
  compiling, rc.11 shipped a tt-muncher that scanned the `derive:` list and silently dropped
  the redundant token before it could produce a second impl.

  That accommodation is gone, and nothing replaces it: no deprecation, no `compile_error!`,
  no warning. A declaration still naming the token now fails with
  `E0119: conflicting implementations of trait ConstantTimeEq`, pointing at the macro
  expansion. **Migration is to delete the token.** Nothing about the generated type changes
  — `ct_eq` is still emitted automatically on every shaped arm, gated only on the `ct-eq`
  feature as before.

  One caveat worth knowing before you go looking: with `ct-eq` **off** (it is not a default
  feature) both impls are discarded, so an offending declaration still compiles and the
  break only surfaces when someone enables the feature.

  The machinery removed is `__sg_newtype_base_ct_eq!` — four arms of recursive token
  munching, replaced by `__sg_newtype_ct_eq!($name)`, a flat emitter modelled on the
  `__sg_newtype_len!` that already sat beside it at all three call sites. Net −62/+46 lines
  across the macro layer, and one less recursive expansion for anyone reading `cargo expand`
  output.

- **`ConstantTimeEq` remains a real `derive:` option on the `generic` arms, and is now
  actually tested.** It cannot be automatic there: an arbitrary inner type may or may not
  implement the trait, and nothing readable off the tokens decides it. Removing the shaped
  arms' accommodation left that opt-in with no coverage anywhere in the suite — every
  declaration that named the token was on a shaped arm — so
  `tests/macros_suite/newtype_generic_ct_eq.rs` now pins it with a caller-defined payload
  that implements `Zeroize`, `FixedStorage`, `SentinelValue` and `ConstantTimeEq`, alongside
  a second newtype over the same payload declared *without* the token. The pair fails loudly
  if the `generic` arm ever starts emitting the impl on its own.

### Fixed
- **`cargo doc --features=full` did not build.** Three doc comments link to `std` items
  this crate touches through gated impls — `io::Write` on `Dynamic<Vec<u8>>` and on
  `SlotWriter`, `io::Read` on `DynamicReader` — and `full` does not enable `std`. Without
  that feature the name `std` is not in scope at all, so rustdoc had nothing to resolve
  against and `-D warnings` turned each link into an error.

  The links are correct and are left alone: they resolve on docs.rs, which builds with
  `all-features`, so published documentation was never affected. `#[cfg(doc)] extern crate
  std;` brings the name into scope for doc builds only — `cfg(doc)` is set by rustdoc and
  nothing else, so no real build is touched, `no_std` or otherwise — and the links now
  resolve in every feature combination rather than only the one docs.rs happens to use.

  CI could not have caught this: the rustdoc job runs `--all-features`, which enables
  `std`. What broke was a plain `cargo doc --features full`, which a contributor runs and
  no job does. Found on `release/0.8`, whose rustdoc job builds `--features=full` and
  therefore did fail; that line has carried the fix since 0.8.0-rc.14, so this brings the
  0.9 line level rather than introducing anything.

## [0.9.0-rc.12] - 2026-09-15

> Published to crates.io on the `v0.9.0-rc.12` tag.

### Changed

- **BREAKING: `Dynamic::<Vec<u8>>::new_with` takes the length and hands its closure a sized,
  pre-zeroed `&mut [u8]` — `new_with(len, |slot| …)` — and gains a fallible twin,
  `try_new_with(len, |slot| …)`.** The closure used to receive an empty `Vec<u8>` to grow.
  It now receives exactly `len` bytes, every one of them zero, living in the payload buffer
  the constructor allocates to hold them. That buffer is one of two allocations the call
  makes, not the whole cost of it — `Dynamic<Vec<u8>>` is a `Box<Vec<u8>>`, so there is a
  second, small allocation for the `Box` header no matter how the `Vec` inside it was
  built. What the signature buys is not a lower count but a fixed shape: the payload
  allocation is exactly `len` bytes, so capacity equals length and the wrapper never holds
  slack, and because the closure holds a slice rather than a container, growth is not
  something it can spell.

  **The old signature was the defect its own documentation warned about.** A `Vec` that
  outgrows its capacity asks the allocator for a new block, copies the secret across, and
  frees the old block **without wiping it**. `new_with` handed the closure a zero-capacity
  `Vec`, so any fill that grew it did exactly that, inside the constructor whose entire
  reason to exist was to write the secret where it would live and nowhere else. The number
  is already in this file, under rc.9: a byte-by-byte fill of a 1008-byte secret abandoned
  **1016 secret bytes across 7 blocks**. rc.9's response was advice — pre-size inside the
  closure with `reserve_exact`, or build the value first and use `Dynamic::new` — which
  fixed the recommendation and left the constructor. The constructor's own module docs
  meanwhile said it existed "for consistent API idiom, not for stack-residue avoidance", and
  that framing is how the hazard read as a footnote rather than a bug: a method offered for
  symmetry is not one anybody audits for what it does with the heap.

  A real consumer shipped the growing form and it survived review, and that is the finding
  worth recording, because three properties made this a trap rather than a sharp edge. The
  failure mode is precisely the one the API is there to prevent, so a reader who reached for
  `new_with` had already decided to care about copies and was rewarded with one. It is
  silent in every direction: the wrapper still zeroizes whatever it ends up holding — rc.9
  measured 0 non-zero bytes of 2016 after growth — so drop-time instrumentation, the
  `Debug` redaction and every test that looks at the finished value all report success,
  while the abandoned copy sits in a block nothing will ever name again. And it is
  *inconsistently* unsafe. One `extend_from_slice` into an empty `Vec` performs its first
  and only allocation and frees nothing, because there is no earlier block to free; the
  second push past that capacity is the one that abandons a buffer. The crate's own
  `from_random` sat on the safe side of that line — a single `resize` from empty — so the
  in-tree usage taught that the pattern was fine, and it was, right up to the second call.
  An API that works the first time and leaks the second is one that trains its callers into
  the failure.

  Making the length part of the signature removes the hazard from the slot, not from
  everything the closure touches. The slot itself is a `&mut [u8]`: `push`,
  `extend_from_slice`, `reserve` and `shrink_to_fit` do not exist on it, so *that*
  allocation — the one the wrapper owns and will protect — cannot be grown and abandoned.
  It says nothing about the closure body, which is ordinary Rust and can allocate whatever
  it likes. The natural migration for a multi-part fill builds the pieces into a `Vec` —
  call it `material` — right there in the closure, then copies the result into the slot;
  that `Vec` grows and abandons its own intermediate blocks exactly as the old `new_with`
  argument did, and the new signature neither sees it nor stops it, because it is a local,
  not the slot. Temporaries the closure grows are still the caller's problem. The way to
  avoid building one is `SlotWriter::push_slice` (below): appending each piece straight
  into the slot instead of into a scratch buffer leaves no `material` to abandon. That is
  why the change is to the type and not to a doc comment — and why `SECURITY.md`'s list of
  routes to a growable `&mut` no longer names the `new_with` closure, while it still names
  `with_secret_mut`, `expose_secret_mut` and `as_wrapper_mut`, which hand out a container.

  **The zero fill is a guarantee, not an implementation detail.** A slot arriving zeroed
  is the obvious way to build one, and it would have been easy to leave it as a property a
  reader could notice and quietly depend on. The reason to promise it instead is that
  callers use the tail as real input. A 40-bit RC4 key is five bytes of derived material
  followed by eleven zeros, and the key schedule consumes those eleven bytes exactly as it
  consumes the first five: they are input, not padding. A slot that merely *happened* to be
  zero would produce a different cipher on the day it was not, and produce it silently — a
  wrong key, not an error, with no assertion anywhere in a position to notice. So the
  rustdoc states the zero tail as a contract, and `SlotWriter` (below) leans on it for the
  short-write case.

  **`try_new_with(len, f)` is the same constructor for a fill that can fail.** `f` returns
  `Result<(), E>`, `E` is free — not pinned to any error type of this crate's, not bounded
  at all, so a consumer returns their own error straight out of the closure — and **on
  `Err` the partial write is zeroized before the error is returned**, because the slot
  lives in a `Zeroizing` that drops on the way out.

  That last property is the one worth arguing for, and the argument comes from an
  upstream decoder rather than from symmetry with `Fixed::try_new_with`. Decoders that
  write into a caller-supplied buffer routinely leave real output in it when they fail.
  `miniz_oxide`'s `decompress_slice_iter_to_slice` documents precisely that: *"This will
  fail if the output buffer is not large enough, but in that case the output buffer will
  still contain the partial decompression."* Feed that decoder a slot, and a failed decode
  leaves real plaintext — the prefix that decompressed before the bad byte — sitting in
  it. The obvious implementation, fill a buffer and wrap it only on success, would abandon
  that prefix unwiped on every malformed input, and malformed input is the case an attacker
  chooses. A guarantee the upstream documentation makes necessary argues better than one
  made for tidiness, so the rustdoc quotes it.

  It is pinned by what it wipes, not by what it returns. `tests/heap_zeroize.rs` adds
  `check_try_new_with_err_zeroed_vec`, which poison-fills the slot, writes a partial
  prefix, pins the slot's pointer, returns `Err`, and has the allocator proxy assert that
  the block reached `dealloc` holding all zeros. Asserting only that `Err` came back would
  pass against a constructor that leaked the entire partial write, because a freed buffer is
  not something a test can name afterwards — unless it watches the free. The error type in
  that test implements nothing at all, not `Debug`, not `Error`, so any bound later added
  to `E` stops the file compiling, which is the cheapest alarm available for that promise.

  **`from_random(len)` and `from_rng(len, rng)` are rewritten onto the new constructors,
  and the first thing the new API did was delete the workarounds written for the old one.**
  `from_rng` carried the captured-local shape — `let mut result = Ok(()); … result.map(|_|
  this)` — that rc.11 retired from `Fixed::from_rng`, because `new_with` could not report
  failure. It is now `Self::try_new_with(len, |slot| rng.try_fill_bytes(slot))`. Both
  constructors also lose a `v.resize(len, 0)` that only ever existed to size a buffer that
  now arrives sized. Same observable behaviour, and the strongest evidence available that
  the signature is the right one.

  **`dynamic_newtype!`'s `Vec<u8>` arm forwards both.** `new_with(len, f)` and
  `try_new_with(len, f)` are emitted on any `Vec<u8>` newtype, the way the arm already
  forwarded the old `new_with`. The `generic` arm still forwards neither, and the reason is
  sharper than it was: a sized byte slot is meaningless for an arbitrary inner type, so
  there is nothing to forward.

  **Migration.** There is no deprecation. Every existing call fails with
  `error[E0061]: this function takes 2 arguments but 1 was supplied`, and since that
  diagnostic carries no `note =` text, the rustdoc on `new_with` opens with a section
  addressed to whoever arrives from it. A deprecation window was considered and declined:
  this is a release-candidate line, a consumer on an RC has signed up for breaking changes,
  and a deprecated constructor that keeps abandoning secret bytes for a release is not a
  softer landing than a compile error that stops it today.

  | Was | Now |
  |---|---|
  | `new_with(\|v\| { v.extend_from_slice(&m); v.resize(16, 0); })` | `new_with(16, \|slot\| slot[..m.len()].copy_from_slice(&m))` |
  | `new_with(\|v\| v.resize(len, 0)); …` then fill via `with_secret_mut` | `new_with(len, \|slot\| …)` — fill in place |
  | `let mut r = Ok(()); let s = new_with(\|v\| { …; r = fill(v); }); r.map(\|_\| s)` | `try_new_with(len, \|slot\| fill(slot))` |
  | length not known before the fill | `Dynamic::new(Vec::new())` then `std::io::Write` (needs `std`) |

  The last row is not a gap. The `io::Write` impl is the sanctioned path for a secret of
  unknown length and wipes every buffer it abandons, and its rustdoc now leads with that
  rather than with its carve-outs. The pair is complete — length known, `new_with`; length
  not known, `Write` — and there is no third case that needs a growable closure.

  **What this does not close.** This removes the reallocation hazard from *inside*
  `new_with`. It does nothing about a value you grew yourself before handing it over:
  `Dynamic::new(v)` moves `v`'s current allocation in and wipes that one, but every block
  `v` abandoned while you built it is already on the heap and already unwiped, and
  `From<&[u8]>` copies and leaves your source where it was. A reader who migrates their
  `new_with` calls and stops will believe they are done, and for one consumer surveyed the
  `new_with` site was one of five wrapper constructions and the only one this change
  reaches. The other four are governed by how the value was built — `with_capacity` at the
  final size, or one `resize`, then a move — which is the guidance `SECURITY.md`'s
  constructor table now gives, and which no signature can enforce.

- **New: `SlotWriter`, an append cursor over a fixed slot.** A sized slot fixes the
  reallocation hazard by taking away growth, and the price is that concatenation becomes
  offset arithmetic: `slot[..7].copy_from_slice(LABEL); slot[7..7 + id.len()]
  .copy_from_slice(suite_id);` and so on, by hand. That trades a reallocation hazard for an
  **offset hazard**, and in byte-exact wire-format code the second is the worse of the two.
  A wrong bound in an HPKE-style labelled concatenation derives the wrong key and then
  runs, and nothing downstream is in a position to say so; a realloc at least leaves the
  right bytes in the right place.

  `SlotWriter::new(slot)` keeps the slot as the primitive and restores the append shape on
  top of it: `push_slice`, `push_byte`, `position`, `remaining`, `is_full`. **Overrun
  panics**, and the message names the shortfall — how many bytes were wanted and how many
  were left — because the useful question when it fires is which length calculation was
  wrong. Running past the end of a secret's buffer is a bug, not a condition to recover
  from. Anything left unwritten keeps the slot's zeros, which is the 40-bit-key case above
  and is why the zero fill had to be a contract for this type to be sound. The writer owns
  nothing and zeroizes nothing; borrowed from inside `new_with`, it inherits the wrapper's
  panic-safety, since unwinding drops the `Zeroizing` and wipes whatever was written.

  Under `std` it also implements `io::Write`, and there an overrun is reported as
  `ErrorKind::WriteZero` — but that is `write_all`'s doing, not a property of every call.
  `write` follows the trait's ordinary contract: it errors only once `remaining()` is
  already 0, and a call that arrives before then with more bytes than fit does not fail —
  it writes `min(buf.len(), remaining())` and returns `Ok(n)`, a valid short write. What
  turns that into an error is `write_all` looping on the `Ok(n)` and handing the leftover
  back to `write` on the next pass, which is the call that finds `remaining() == 0` and
  fails. A caller that invokes `write` directly and does not check the count it returns
  gets a silent short write, not an error — the slot's zero tail again, this time from an
  interface that had a chance to report it and, for that call, does not. That path exists
  so a slot can be handed to foreign code — a serializer, an encoder, a hasher's output
  sink — that cannot be asked to respect a length, and for which `write_all`'s error is
  the way to say stop. Available with no features; exported at the crate root as
  `secure_gate::SlotWriter`.

### Removed

- **BREAKING: `Dynamic::<String>::new_with` is deleted outright, with no replacement.** It
  had the identical defect: an empty `String` handed to a closure, every growth past
  capacity abandoning the previous block unwiped. Unlike the `Vec<u8>` form, it cannot be
  fixed by the same move, because no sized slot is possible for text. A `String` must hold
  valid UTF-8 and characters have variable byte widths, so a fixed window of `len` bytes
  is not somewhere arbitrary text can be written — a closure given `&mut [u8]` could
  produce a byte sequence that is not a `String`, and one given `&mut str` cannot write at
  all. A version that kept the growable `String` would keep the leak; a version with a byte
  slot would not be a `String` constructor. Neither is worth a method, so there is none.

  The `dynamic_newtype!` `String` arm no longer emits a `new_with` either, and its rustdoc
  says why rather than leaving the asymmetry with the `Vec<u8>` arm unexplained. The
  `generic String` compile error, which used to list `new_with` among what that spelling
  withholds and called it "the in-place constructor that builds the secret inside the
  protected buffer", now lists only `SecretLen` and `From<&str>` — the description was
  true of neither arm, and there is no longer anything to withhold.

  **Migration.** There is no deprecation, for the reason given above. A call fails with
  ``error[E0599]: no function or associated item named `new_with` found for struct
  `Dynamic<String>` ``. The replacement is to build the `String` pre-sized yourself —
  `String::with_capacity(len)`, filled once — and pass it to `Dynamic::new`, which
  **moves** that buffer in rather than copying it, so the allocation you filled is the
  allocation the wrapper wipes. `From<&str>` is the convenient spelling and the leaky one:
  it copies, and your original is left behind. The caveat above applies with full force
  here, since the `String` path now has no in-wrapper construction at all: `new` is only
  as safe as how the value was built, and a `String` grown by `push_str` before the move
  has already abandoned its intermediates.

## [0.9.0-rc.11] - 2026-09-15

> Published to crates.io on the `v0.9.0-rc.11` tag.

### Added

- **`Fixed::try_new_with` — in-place construction from a fill that can fail.**
  [`new_with`](https://docs.rs/secure-gate/latest/secure_gate/struct.Fixed.html#method.new_with)
  hands a closure the wrapper's own storage, so a secret is written where it will live and
  never occupies a caller-owned buffer. It is the constructor `SECURITY.md` tells people to
  prefer. Its closure could not fail — and the most common way to obtain a secret is to read
  it from a file, a socket or a device, which can. The safe shape and the fallible shape did
  not compose.

  What callers did instead was route the error out of the closure through a captured local:

  ```rust
  let mut result = Ok(());
  let this = Self::new_with(|arr| { result = rng.try_fill_bytes(arr); });
  result.map(|_| this)
  ```

  That is not a hypothetical. It was `Fixed::from_rng`'s own body, written that way because
  there was no alternative, and it is correct only for as long as nobody deletes the last
  line — do that and a failed fill yields a half-written secret that looks fine. `from_rng`
  is now `Self::try_new_with(|arr| rng.try_fill_bytes(arr))`, which is the same behaviour and
  the strongest evidence available that the signature is the right one: the first thing the
  new API did was delete the workaround it was designed to retire.

  **On `Err` the partial write is zeroized before the error is returned.** The wrapper is
  constructed *before* the closure runs, so it is a live local for the whole fill and `Drop`
  wipes whatever the closure managed to write. This is the half that the obvious
  implementation — fill a buffer, wrap it only on success — gets backwards, so it is pinned
  by a test that records the actual value wiped rather than asserting the `Result`.

  Forwarded by every `fixed_newtype!` arm that already forwards `new_with`: the size-literal
  arm, the literal-array `generic [T; N]` arm, and the opaque `generic T` arm. Outside the
  feature relays, so it resolves with no features at all — which matters most on the targets
  where `Fixed` is the only wrapper there is.

  `Dynamic` does not get a counterpart yet. `Dynamic::new_with` hands its closure an empty
  `Vec`/`String` to grow rather than a sized slot, which puts it directly against the
  reallocation-residue guidance in `SECURITY.md`; that deserves answering on its own rather
  than in passing.

  **On the name.** Elsewhere on `Fixed`, `try_` marks a constructor that *parses* untrusted
  input — `try_from_hex`, `try_from_base32`, `TryFrom<&[u8]>` — while `from_rng` is fallible
  and keeps `from_`. Read strictly, that argued for a different name here. It loses to the
  wider convention: across Rust `try_x` is the fallible form of `x` (`try_reserve`,
  `try_lock`), and that is the meaning a reader arrives with. A name nobody guesses is worse
  than a prefix carrying two related senses, so the rustdoc states both rather than leaving
  an unstated rule with an exception in it.

  Requested by a downstream consumer (aescrypt-rs) whose AES Crypt v0–v3 reader fills
  `[u8; N]` spans from a stream.

### Changed

- **`fixed_newtype!`'s size-literal arm implements `ConstantTimeEq` without being asked.**
  A `[u8; N]` newtype now carries `ct_eq` whenever the `ct-eq` feature is on, the way
  `Fixed<[u8; N]>` itself always has.

  The asymmetry this removes ran the wrong way. `Fixed<T>` implements `ConstantTimeEq` for
  any `T` that does, so `pub type MacTag = Fixed<[u8; 32]>;` has had `ct_eq` for free since
  the trait existed. The newtype — the spelling this crate's README teaches first and calls
  the safer of the two — did not, unless the declaration also named
  `derive: [ConstantTimeEq]`. A reader who took the documented advice got *fewer* security
  properties than one who ignored it, and the missing one was constant-time comparison,
  whose alternative is a timing leak. An extra token on the recommended side is the wrong
  way round for that trait in particular.

  Nothing was silently weak, and the distinction matters for how this is classified. With
  no impl, no `Deref`, and `==` deliberately unimplemented on every wrapper here,
  `tag_a.ct_eq(&tag_b)` on a newtype missing the derive is
  `error[E0599]: no method named ct_eq` — not a variable-time fallback. There was nothing
  for it to degrade *to*. The defect was an incentive, not a vulnerability, which is why
  this sits under `Changed` rather than `Security`.

  **No migration.** `derive: [ConstantTimeEq]` on a size-literal newtype still compiles and
  still means what it says: the token is redundant there now, not removed. Emitting the
  impl twice would be `E0119`, so the derive list is scanned and that one token dropped
  before the rest reach the base expansion — neighbouring options are unaffected, in either
  order. Deleting it from existing declarations is optional tidying.

  It remains a genuine opt-in everywhere else. On the `generic` arms the inner type may or
  may not implement `ConstantTimeEq` — `[i16; 256]` does not — so nothing the macro can
  read off the tokens decides it and the declaration still must. The same argument applies
  to `dynamic_newtype!`'s `String` and `Vec<u8>` arms, which follow in the entry below.

  Reported by a downstream consumer (aescrypt-rs) migrating a full AES Crypt v0–v3
  implementation onto the newtype macros, whose three HMAC-tag comparison sites were the
  ones that would have silently lost `ct_eq` in the move from plain aliases.

- **`dynamic_newtype!`'s `String` and `Vec<u8>` arms implement `ConstantTimeEq` without being
  asked, matching `fixed_newtype!`.** The heap arms carried the identical asymmetry the
  size-literal arm did, for the identical reason: `Dynamic<T>` implements `ConstantTimeEq`
  for any `T` that does, so `pub type ApiKey = Dynamic<String>;` always had `ct_eq` and
  `dynamic_newtype!(pub ApiKey, String)` did not. Correcting one and not the other would
  have left the crate recommending newtypes while two of its four nominal arms still
  charged an extra token for constant-time comparison.

  The shared helper is renamed `__sg_newtype_base_ct_eq!` — it was `__sg_newtype_base_bytes!`
  when the size-literal arm was its only caller, and that name stopped describing it the
  moment `Dynamic<String>` became one. It is `#[doc(hidden)]` and internal; no caller
  outside this crate names it, and rc.11 was unpublished when the rename landed.

  As on the size-literal arm, `derive: [ConstantTimeEq]` stays accepted and inert, so no
  declaration written against an earlier release candidate changes meaning. The `generic`
  arm is untouched: an arbitrary inner type may or may not implement the trait.

  One property does *not* transfer from the fixed arms, and the rustdoc now says so where
  the token used to be documented: `ct_eq` on a variable-length secret short-circuits when
  the lengths differ, so only the equal-length comparison runs in constant time. Where the
  length itself is sensitive, `fixed_newtype!` is the answer.

### Testing

- **The fallible constructor's error path is pinned by what it wipes, not by what it
  returns.** `tests/lifecycle_trace_handoff.rs` is the only instrument here that can watch a
  `Fixed` being cleared — the secret lives on the stack, so the allocator-proxy suite never
  sees it, and reading the slot after drop is unavailable under `#![forbid(unsafe_code)]`.
  Its recording inner type reports the value present at each wipe, so the test asserts that
  `0x0BAD_F00D` specifically was written and then cleared. Asserting only that an `Err` came
  back would pass against an implementation that leaked the whole partial write.

  A second case runs the same thing through a `generic` newtype, which pins that the macro's
  forwarded `try_new_with` reaches `Fixed::try_new_with` instead of reimplementing it: a
  forward that rebuilt the value would not wipe, and would satisfy any test that only looked
  at the `Result`.

- **Both `trybuild` snapshots moved, for different reasons, and only one of them is
  noise.** `fixed_zero_size.stderr` embeds the line of the `NON_ZERO_SIZED` assertion in
  `src/fixed.rs`, so the doc rows added above it shifted `298` to `300` — the known
  fragility, re-blessed with no meaning.

  `fixed_reallocating_inner.stderr` grew by sixty lines, and that part is evidence.
  Its fixture declares `fixed_newtype!(pub LeakyBytes, generic Vec<u8>)`, and the
  compiler now reports the `FixedStorage` violation once per forwarded constructor
  rather than twice — `new`, `new_with`, and `try_new_with`. The snapshot getting longer
  is the guard demonstrating it covers the new constructor too, which is worth more than
  a separate fixture asserting the same thing would have been.

- `tests/macros_suite/newtype_surface.rs` pins both halves: the impl arrives on a
  declaration with no `derive:` list at all (including at `N = 900`, well past the
  32-element ceiling `Default` would impose), and the pre-rc.11 spelling stays inert rather
  than becoming a duplicate impl. A third case puts the redundant token *between* two live
  options and asserts both survive it.

  A parallel test does the same for the `String` and `Vec<u8>` arms, and adds the one
  assertion that has no fixed-arm counterpart: two secrets of differing length compare
  unequal rather than panicking, which is the documented short-circuit and the reason the
  constant-time guarantee covers contents but not length.

## [0.9.0-rc.10] - 2026-09-14

> Published to crates.io on the `v0.9.0-rc.10` tag.

### Security

- **Raised the `base32ct` floor to `0.3.1`; `0.3.0` panics on attacker-supplied input.**
  The requirement was a bare `"0.3"`, which admits `0.3.0`. That version sizes its output
  buffer from the decoded length but indexes it from the encoded remainder, so an unpadded
  input whose trailing block is 1, 3 or 6 characters long — exactly the block lengths
  unpadded Base32 cannot represent — indexes out of bounds and panics instead of returning
  `Err`. `try_from_base32` hands caller-supplied strings straight to that decoder, and the
  no-alloc path that writes into a caller-supplied buffer panics as well, so disabling
  `alloc` was not a mitigation. Upstream fixed it in `0.3.1` ([RustCrypto/formats#2242](https://github.com/RustCrypto/formats/issues/2242)).

  Our own builds were never affected: `Cargo.lock` has resolved `0.3.1` throughout. A
  lockfile does not travel to dependents, though, so a downstream crate resolving
  `base32ct` for itself could land on `0.3.0` — most plausibly from a lockfile written
  during the two days that version was the newest release. The floor is what prevents
  that; it costs no MSRV, because `0.3.0` and `0.3.1` declare the same `rust-version`.

  `tests/encoding_suite/base32.rs` now walks several `len % 8` congruence classes rather
  than the three shortest cases, so the property is pinned if the floor is ever loosened.

  Note that no RUSTSEC advisory exists for this, so `cargo audit` does not flag it.

### Added

- **`fixed_newtype!` gained an arm for literal arrays, which forwards `SecretLen`.**
  `generic [i16; 256]` now matches a dedicated `generic [$t:ty; $n:literal]` arm instead
  of falling through to the opaque one, so the newtype carries its own `len()` and
  `byte_len()`: the element count and `N * size_of::<T>()` respectively — 256 and 512 for
  an ML-KEM secret polynomial, 60 and 240 for an AES-256 key schedule.

  The capability was never missing, only unforwarded. `impl SecretLen for Fixed<[T; N]>`
  is bounded on `T: Zeroize` alone, so the base wrapper has always answered both questions
  correctly. What the arm removes is a standing reason to grant `derive: [IntoWrapper]`:
  that token is the documented downgrade toward the base type, to be audited like
  `expose_secret()`, and reaching for it merely to measure a secret was a nominal-safety
  cost paid for a length. The earlier rationale — that "a length in elements is not the
  byte length callers expect" — argued from meaning when the real obstacle was visibility;
  `SecretLen` has both units and the macro can tell an array from a struct whenever the
  array is written out.

  The arm needs a *literal* length. `generic [i16; KEY_LEN]`, and any array named through
  a type alias, are different token sequences and still take the opaque arm — the same
  token-versus-type remainder `dynamic_newtype!` already documents for paths. `generic
  [u8; N]` is still refused ahead of both arms: write the size literal.

  `From`, `TryFrom`, the encoders and the RNG constructors remain absent from every
  `generic` arm. The encoders have no defined byte order over `[i16]`, and byte order is
  not the whole of it — the canonical encoding of these secrets is domain-specific, so a
  raw element dump would round-trip in this crate and disagree with every implementation
  outside it. RNG is a separate question, tracked in #219.

### Changed

- **BREAKING: `fixed_newtype!(pub Z, generic [T; 0])` is now rejected at the declaration.**
  A zero-length secret was already impossible to *construct* — `Fixed::new` and
  `Fixed::new_with` carry a `const` assertion rejecting a zero-sized inner value — but that
  is a post-monomorphization error: `cargo check` does not see it, and a library whose only
  such construction sits behind an `#[inline]` function builds, tests and publishes green.
  The array arm emits the same `const _: () = { let _ = [(); N][0]; };` guard the
  size-literal arm has always carried, so the error now lands on the declaring line. Code
  that declared such a newtype without ever constructing one compiled before and does not
  now; nothing that could run has changed.

  The two guards are complementary rather than redundant, because they measure different
  things: the macro counts a *length*, the wrapper measures a *size*. `generic [(); 4]` has
  a non-zero length and is still zero-sized, so it clears the declaration-site guard and is
  caught at construction — which is what `tests/compile-fail/fixed_zero_size.rs` now pins,
  having moved off `generic [i16; 0]` for exactly this reason.

- **BREAKING: `Fixed<T>::new_with` is no longer `[u8; N]`-only, and existing call
  sites may need a type annotation.** It moves to the generic impl, bounded by
  `FixedStorage + SentinelValue`, so a non-byte array (`[i16; 256]`, `[u32; 60]`)
  gets the same in-place constructor the byte arm already had: the slot starts as
  `T::sentinel_value()` and the closure writes into the wrapper's own storage.
  `fixed_newtype!`'s `generic` arm forwards it. The specialised `NON_ZERO_LEN`
  assertion on `Fixed<[u8; N]>` is gone; both `new` and `new_with` now read
  `NON_ZERO_SIZED`. Tracking: #215.

  **Migration.** The closure's parameter type is now only known once `T` is, and
  a return type alone does not resolve it in time — the closure body is checked
  first. So `fn k() -> Fixed<[u8; 32]> { Fixed::new_with(|a| a.fill(1)) }`, which
  compiled through rc.9, now fails with **E0282**, `type annotations needed for
  &mut _`. Name the type in either position:

  ```rust
  Fixed::<[u8; 32]>::new_with(|x| x.fill(1))   // on the type
  Fixed::new_with(|x: &mut [u8; 32]| x.fill(1)) // or on the closure parameter
  ```

  Only bare `Fixed::new_with` is affected. Newtypes built by `fixed_newtype!` are
  not: their generated `new_with` has a concrete parameter type on both arms. A
  closure whose body needs no method resolution on the parameter also still
  infers. This is a source break with no runtime or codegen change.

- **BREAKING: `fixed_newtype!(pub K, generic [u8; N])` is a compile error at the
  declaration.** It was strictly dominated by `fixed_newtype!(pub K, N)`: same
  payload, no `SecretLen`, no `From`/`TryFrom`, no encoders, no `from_random`.
  `dynamic_newtype!` already refused the analogous spellings (`generic Vec<u8>`,
  `generic String`). Write the size literal. All four tails are pinned by
  `tests/compile-fail/fixed_newtype_generic_bytes_rejected.rs`. The zero-size
  trybuild moves from `generic [u8; 0]` to `generic [i16; 0]`, because the
  former now dies at the domination check and would never reach `Fixed::new`.
  Tracking: #215.

## [0.9.0-rc.9] - 2026-09-13

> Published to crates.io on the `v0.9.0-rc.9` tag. Only `secure-gate` has ever been
> published — `secure-gate-compat` never was.
>
> The heading carries a date because the entries below settle what the alias macros are,
> and that answer should not sit under "Unreleased" while the macros themselves are
> already gone from the code.

### Added

- **`fixed_newtype!(pub Name, generic T)` — the `Fixed` counterpart of the `generic` arm.**
  `dynamic_newtype!` has accepted `generic T` since rc.8, for an inner type that is neither
  `String` nor `Vec<u8>`. `fixed_newtype!` had no such arm, for a reason that was about the
  macro rather than the wrapper: it takes a size literal, so the token-matching ambiguity
  that forced `dynamic_newtype!`'s explicit marker never arose, and nobody went looking for
  the gap.

  The gap is real, and it is widest exactly where `Fixed` matters most. On a `no_std` target
  there is no allocator, so there is no `Dynamic` at all and `Fixed` is the only wrapper —
  and a secret on such a target is frequently not a byte array. An ML-KEM secret polynomial
  is `[i16; 256]`; Ed25519 scalar limbs are `[u64; 4]`; an AES-256 expanded key schedule is
  `[u32; 60]`, as secret as the key it was derived from. All three are valid `Fixed<T>`
  today, because `Fixed<T: Zeroize>` and its `RevealSecret` impl are generic over `T`. None
  of them could be given a nominal type by macro.

  ```rust
  // An ML-KEM secret polynomial, on a target with no allocator.
  fixed_newtype!(pub Poly, generic [i16; 256]);
  let p = Poly::new([0i16; 256]);
  assert_eq!(p.with_secret(|c| c.len()), 256);
  ```

  The arm emits the struct, redacted `Debug`, `RevealSecret`, `RevealSecretMut`, `Zeroize`,
  `ZeroizeOnDrop`, any `derive:` tokens, and a `const fn new`. It deliberately omits
  `SecretLen`, `new_with`, `From`, `TryFrom`, the encoders and the RNG constructors: none of
  those has a meaning for an arbitrary `T`, which is the same trade `dynamic_newtype!`'s
  generic arm already makes. Writing the word `generic` is how a caller says they know.

  `fixed_newtype!` also gained a catch-all arm, so an inner type that is neither a size
  literal nor marked `generic` is now a `compile_error!` naming both fixes instead of
  rustc's "no rules expected this token".

### Changed

- **BREAKING: `dynamic_newtype!(pub Name, generic Vec<u8>)` and `generic String` are now a
  compile error at the declaration.** Both were strictly dominated spellings. The `generic`
  arm emits only the shape-independent surface, so either one took the same growable payload
  as the shaped arm and then withheld the methods that handle it: `SecretLen`, `From`,
  `new_with`, the encoders, `from_random`, and — for `Vec<u8>` under `std` — the
  `std::io::Write` impl, which is the only growth path that wipes the buffer it abandons.
  Same payload, less API, and for bytes no safe way to grow at all. The fix is to delete one
  word: write `Vec<u8>` or `String` and the shaped arm gives the full surface.

  **This is not the `FixedStorage` move, and should not be read as one.** That bound closed a
  *wrong wrapper* — `Fixed` claims to own no heap and a `Vec` owns one — and it lives in the
  type system, so it catches aliases. This is a *wrong arm of the right wrapper*:
  `Dynamic<Vec<u8>>` is exactly the type you should be holding, and no bound, marker or
  deny-list is added to `Dynamic`. The precedent is the one the `generic` marker itself set:
  when a spelling produces a strictly worse API than a same-crate alternative, fail at the
  declaration and name the alternative.

  **What it does not catch, stated plainly rather than implied.** The reject matches literal
  tokens, exactly as the shaped `String` and `Vec<u8>` arms always have. `type MyBytes =
  Vec<u8>` and path-qualified spellings such as `alloc::vec::Vec<u8>` are different token
  sequences and still land on the reduced arm. That remainder is documented, not chased: a
  token deny-list does not become type-level by getting longer, and `std::`-qualified,
  `Vec<u8, A>`, turbofish and re-exported spellings would each need their own arm while still
  leaving others out. `tests/macros_suite/newtype_surface.rs` pins the remainder as compiling,
  so closing it later has to be a deliberate decision rather than a drive-by.

  The catch-all message changed too, and that part is a bug fix. It previously told anyone
  who wrote a path-qualified inner type to "write `generic <type>` to accept the reduced API
  on purpose" — advice that *manufactured* the very form this entry rejects. It now says to
  write the literal token, and warns that reaching for `generic` to silence the error lands
  you on the reduced arm with the growable payload and none of the methods that handle it.

  **Migration.** Delete the word `generic`. No in-tree caller used either form. Non-byte,
  non-string inner types — `generic Vec<u32>`, `generic [u32; 60]`, a custom struct — are
  untouched, which is what the `generic` arm exists for.

- **`CloneableSecret` carries `#[diagnostic::on_unimplemented]`, so the error explains itself.**
  Cloning a secret wrapper has always required this marker on the inner type, and the gate
  always held — but the message was a bare `the trait bound `[u8; 32]: CloneableSecret` is not
  satisfied`, naming a marker the caller had likely never heard of and saying nothing about
  what to do with it. It now explains that cloning makes a second copy every one of which must
  be zeroized, that the fix for a type you define is an empty `impl CloneableSecret` block next
  to its `Zeroize` impl, that for a foreign type the orphan rule rejects that with E0117 and a
  local newtype is the way round it, and that arriving here from `#[derive(Clone)]` means the
  derive forwarded to the wrapper's `Clone`.

  The route that made this worth doing is `#[derive(Clone)]` in the attribute slot. Both
  newtype macros accept `$(#[$attr:meta])*` before the name so ordinary `///` comments work, and
  a derive smuggled in there never reaches the friendly `derive: [Clone]` guard — a `:meta`
  fragment is opaque once captured, so the macro cannot inspect it and refuse. That path is now
  pinned by `tests/compile-fail/newtype_derive_clone_attr_slot.rs`.

  **What this does not cover, measured rather than assumed.** With the `cloneable` feature
  **off**, both the trait and the wrapper's `Clone` impl cease to exist, so the failure is
  `Fixed<[u8; 32]>: Clone` and no crate trait appears in the bound chain for a diagnostic to
  attach to. That case keeps the bare message. Reaching it would mean either ungating the trait
  or shipping an always-present `Clone` impl with an unsatisfiable bound, and both make the
  public API worse than the message is bad. The attribute needs Rust 1.78, so this is the 0.9
  line only; the 0.8 line's MSRV is 1.70.

- **BREAKING: `Fixed::new` now requires `FixedStorage` on the inner type, which makes
  `SECURITY.md`'s "`Fixed<T>` is exempt" true instead of aspirational.** That sentence was a
  claim about the shape people were expected to use, not something the type system checked.
  `Fixed<T>` was bounded only by `Zeroize`, so all of these compiled, and measured with an
  allocator instrument, each abandoned an unwiped buffer holding the whole secret on any
  capacity change: `Fixed<Vec<u8>>` and `Fixed<String>` at 1008 of 1008 bytes;
  `Fixed<[Vec<u8>; 2]>`, which hides a growable container inside the very array shape the
  document called exempt; and `fixed_newtype!(pub Name, generic Vec<u8>)`, which was the
  documented, blessed path to all of it. Worse than the `Dynamic` equivalent, because
  `Dynamic<Vec<u8>>` has a safe-growth `io::Write` impl that grows by hand and wipes the old
  allocation, and `Fixed<Vec<u8>>` has nothing. Grepping the repository for `Fixed<Vec`
  returned zero hits, so nothing warned anyone off it while `SECURITY.md` promised the
  opposite.

  `FixedStorage` is a marker with no methods, in the same family as `CloneableSecret`,
  `SerializableSecret` and `SentinelValue`. Implementing it asserts that the type owns no
  buffer whose capacity can change. The crate covers the primitives, `[T; N]` for any `N`
  when the element type qualifies, tuples up to four elements, `Option<T>`, and `Box<[T]>` —
  a boxed slice has a length fixed at construction. `Vec<T>` and `String` are deliberately
  absent.

  **Why a bound rather than another `const` assertion.** The zero-size guard is a
  post-monomorphization `const` error: `cargo check` cannot see it, generic code defers it to
  the instantiation site, and a release build of a library can swallow it entirely. A trait
  bound has none of those properties. Measured against a consumer crate: `Fixed<Vec<u8>>`,
  `Fixed<String>`, `Fixed<[Vec<u8>; 2]>`, `Fixed<Option<Vec<u8>>>` and a tuple containing a
  `Vec` are all `cargo check` errors, and for `fixed_newtype!(pub X, generic Vec<u8>)` the
  error lands on the declaration line rather than at the first construction. A downstream
  generic function cannot launder a `Vec` through either, because the bound propagates to its
  caller.

  A `needs_drop` const assertion was prototyped first and rejected. It classifies every case
  that matters correctly, but it also rejects `#[derive(Zeroize, ZeroizeOnDrop)] struct
  Key([u8; 32])` — the shape the `zeroize` documentation recommends — along with any
  hand-written `Drop` and `Zeroizing<[u8; 32]>`, because all three have drop glue while owning
  nothing heap-allocated. A `const` cannot ask whether a type implements a trait, so it cannot
  be paired with an opt-out either. The marker has no such false positives.

  **Two limits, stated rather than glossed.** It is an assertion, not an enforcement: the
  compiler checks that you wrote the impl, not that it is true, so a type with a `Vec` field
  that implements `FixedStorage` anyway compiles and leaks — verified. The alternative, a
  closed set of blessed types, would destroy the one thing the `generic` arm exists for,
  holding a custom secret on a target with no allocator. And the bound is on `Fixed`, so it
  says nothing about `dynamic_newtype!(pub Name, generic Vec<u8>)`, which has the growable
  payload and, unlike plain `Dynamic<Vec<u8>>`, no `io::Write` escape. That was left as a
  separate decision rather than widened into this one; it is settled below, and settled
  differently — as a macro-arm reject, not a bound on `Dynamic`.

  **`Box<[T]>` was blessed and then un-blessed, because the predicate was wrong.** The trait
  first asked only that a type's capacity cannot change, and a boxed slice satisfies that — its
  length is fixed at construction. An adversarial pass measured the consequence on a shape the
  crate had just permitted: a `Fixed<Box<[u8]>>` holding a 1024-byte secret, mutated with
  `with_secret_mut(|slot| *slot = other_boxed_slice)`, released the original block with **1024
  of 1024** bytes intact, and the same assignment through `expose_secret_mut` did too.
  `Option<Box<[u8]>>` and `[Box<[u8]>; 2]` were permitted by the same impl. The inline
  contrast, `Fixed<[u8; 1024]>` assigned the same way, freed nothing at all, because there is
  no allocation to abandon.

  The residue never required a capacity change: replacing the whole value abandons the
  allocation just as well, and the wrapper wipes what it holds at drop rather than what it used
  to hold. So the contract is now **heap ownership**, not resizability, the `Box<[T]>` impl is
  gone, and all three boxed shapes are refused. The supported shape for a heap-backed secret of
  fixed size is `Dynamic<[u8; N]>`, which allocates once. The rejection is pinned in
  `tests/compile-fail/fixed_reallocating_inner.rs` and the reasoning is recorded beside a test
  in `tests/core_tests.rs`, because a future reader will otherwise be tempted to add the impl
  back for exactly the reason it was added the first time.

  **The migration itself wrote one false assertion, found by a sweep tool and fixed.** The
  twelve marker impls added across the test suite were placed by a script, and eleven were
  truthful — every one wraps an array or a `u64`. The twelfth was not: `cloneable_secret_works`
  in `tests/core_tests.rs` declares `struct CloneKey(Vec<u8>)`, and the script gave it
  `impl FixedStorage for CloneKey {}` so the test would compile again. That is exactly the lie
  the trait documents as possible and the compiler cannot catch — asserting that a type owning a
  `Vec` owns no heap allocation — and it was shipped as part of the change that exists to
  discourage it. Nothing in the test grows the buffer, so there was no live leak; the defect is
  the false assertion sitting where a reader would copy it. The test's own comment says its
  subject is that a clone "owns independent heap memory", which makes `Dynamic<CloneKey>` the
  correct wrapper; it now uses that, with the false impl gone and a note recording what writing
  one looks like. The other eleven were audited the same way.

  **The error now says what to do instead, and names the one configuration that is easy to
  get wrong.** `FixedStorage` carries a `#[diagnostic::on_unimplemented]` attribute, so instead
  of a bare unsatisfied-bound error a consumer reads why the inner type does not qualify, that
  `Dynamic<T>` is the wrapper for a heap-backed secret, and that `Dynamic` needs this crate's
  `alloc` feature. That last clause exists because of a real gap: the claim that `Fixed<Vec<u8>>` is
  dominated "in every feature configuration" is not quite true. A consumer can disable this
  crate's `alloc` while `zeroize`'s own `alloc` is enabled elsewhere in the graph, and in that
  configuration `Vec<u8>: Zeroize` holds, `Fixed<Vec<u8>>` used to compile, and
  `secure_gate::Dynamic` does not exist at all (`error[E0433]` with "the item is gated behind
  the `alloc` feature"). Measured on the commit before this change. The configuration is
  incoherent rather than useful — it says there is no allocator while using one — and the remedy
  is one line of `Cargo.toml`, but the old diagnostic gave no hint of it. Now it does. The
  attribute needs Rust 1.78, so it is on the 0.9 line only; the 0.8 line carries the same
  guidance in the trait's documentation instead.

  **The allow-list had to be completed, and the first version of the diagnostic told a
  falsehood.** A positive marker bound fails closed, which is the right direction for a
  security crate but means a type is refused for two indistinguishable reasons: it owns a heap
  allocation, or nothing has asserted that it does not. The first version of this change only
  blessed the primitives, `[T; N]`, tuples to four and `Option<T>` — so eight heap-free shapes
  that compiled at `0.9.0-rc.9` stopped compiling, measured against the parent commit with a
  consumer crate: the twelve `NonZero` integers, `Wrapping<T>`, `MaybeUninit<T>`,
  `zeroize::Zeroizing<T>`, tuples of five to ten elements, `[NonZeroU32; 4]`, and `Fixed<T>`
  nested in itself. None of them owns a heap allocation.

  What made that a defect rather than an inconvenience is the orphan rule. Every one of those
  types is foreign, so a consumer cannot add the missing impl: `impl secure_gate::FixedStorage
  for core::num::NonZeroU32` in a downstream crate is `error[E0117]`. There was no workaround
  short of changing their own type, and the diagnostic actively misdirected them — it stated as
  fact that the type "owns a heap allocation", which for `(u8, u8, u8, u8, u8)` is simply
  untrue, and then recommended writing the impl that E0117 forbids. Both are fixed: the impls
  above are now present, the message says the type "is not known to be free of heap
  allocations", and it distinguishes the two cases, naming E0117 for the foreign one. Tuples
  stop at ten because that is `zeroize`'s own ceiling — an eleventh element fails the `Zeroize`
  bound before this one is consulted. `tests/core_tests.rs` pins all eight shapes, and
  `tests/compile-fail/fixed_reallocating_inner.rs` pins that `Zeroizing<T>` stays conditional,
  so the wipe-on-drop wrapper cannot smuggle a `Vec` past the bound.

  **Migration.** Nothing for byte arrays, non-byte arrays, tuples, `Option`s, `NonZero`
  integers, `Wrapping`, `MaybeUninit` or `zeroize::Zeroizing`.
  A custom inner type adds one line, `impl FixedStorage for MyKey {}`, next to its `Zeroize`
  impl. A `Fixed<Vec<u8>>` or `Fixed<String>` must become `Dynamic`, which is the wrapper for
  a growable payload. Inside this repository the change touched nine custom inner types across
  five test files and one bench — and one doctest: `SerializableSecret`'s example wrapped a
  `BackupKey(Vec<u8>)` in a `Fixed`, so the crate's own documentation contained an instance of
  the weakness. It now uses `Dynamic`.


- **BREAKING: a zero-sized `Fixed` no longer constructs.** The rc.9 notes recorded that the
  `N = 0` rejection lived inside `fixed_alias!` and nowhere else, so `type Name =
  Fixed<[u8; 0]>;` written by hand bypassed it, and that `Fixed` *could* carry the check
  itself as a post-monomorphization `const` assertion. With the alias macros now gone
  (below), the only guard left would have been the one inside `fixed_newtype!`, so the check
  has moved to where it covers every spelling: `Fixed::new` and `Fixed::new_with` each read
  an associated `const` that asserts a non-zero size. Those two bodies are what every other
  constructor, decoder, RNG entry point and the `Deserialize` impl already funnel through,
  so one assertion each covers the whole surface.

  It is spelled as an associated `const` rather than an inline `const { }` block so that the
  identical hunk builds on the 0.8 line, whose MSRV is 1.70; inline const blocks need 1.79.
  The `#[allow(clippy::let_unit_value)]` on the binding is load-bearing for the same reason:
  binding the unit-valued constant is what forces it to be evaluated, and clippy 1.70 rejects
  every spelling that still triggers the evaluation — a bare path statement and `_ =` are
  rejected by both 1.70 and 1.85, so the allow is the only form clean on both.

  What fires, and where: the error is post-monomorphization, so generic code still compiles
  and the failure appears at the first concrete zero-sized construction. The diagnostic names
  the offending type in the failing constant's path (`Fixed::<[u8; 0]>::NON_ZERO_SIZED`) and
  a `while instantiating` note points at the construction that reached it. Naming the type
  without ever building one still compiles, which is why no guard placed in the type could
  ever make the type unnameable. The `size_of` form also rejects any other zero-sized inner
  type, `Fixed<()>` included.

  **Two limitations, both measured rather than assumed.** First, `cargo check` does not
  report it: a post-monomorphization error is raised during codegen, and `cargo check` stops
  before codegen, so an editor driven by it stays quiet. Second, and more consequential, it
  fires only for a *codegen root*. A non-generic `#[inline]` function in a library is not
  one, and every method these macros generate carries an inline attribute (`#[inline]` on
  the delegating surface, `#[inline(always)]` on `new`, `new_with` and `From::from`), so a
  library crate that writes `fixed_newtype!(pub Empty, generic [u8; 0]);` next to
  `#[inline] pub fn empty() -> Empty { Empty::new([]) }` passes `cargo build`,
  `cargo build --release` and `cargo test` with exit 0 and publishes. The error then appears
  in every downstream crate that instantiates it, pointing into `secure-gate` and at the
  dependency's macro invocation rather than at the consumer's own call.

  Root-ness turned out to depend on the compiler and the profile as well as the attribute,
  which makes the limit broader than "add `#[inline]` and CI goes quiet". Measured on 1.85:
  the same library with a plain non-generic, non-`inline` `pub fn empty()` fails
  `cargo build` and `cargo test` and passes `cargo build --release`, because the
  cross-crate-inlining heuristic added in rustc 1.75 drops a small function from the
  exported root set in an optimized build. On 1.70 it fails in both profiles, so this is the
  compiler's decision rather than anything the crate controls. The documentation now says
  so, and says that instantiating the type in a test or binary is the only reliable check.

  So the guarantee is narrower than "cannot ship", and worth stating exactly: no *value* of
  a zero-sized `Fixed` can exist at runtime, because nothing can construct one, and a binary
  or test that tries fails to compile. What the guard does not do is stop a library from
  exporting an unusable zero-sized API with green CI. Nothing on stable Rust
  moves the check earlier for generic code: a condition on a generic parameter has nothing to
  evaluate until that parameter is known. Three other formulations were tried — an array
  index inside the constant, the same index inline in the function body, and
  `[(); N - 1]` — and they are respectively equivalent, silently ineffective, and rejected
  outright as "generic parameters may not be used in const operations". `fixed_newtype!`
  keeps its own declaration-site guard, which does fire under `cargo check`, because at that
  point the size is a literal.

  `Dynamic` gets no equivalent, and the reason is about the payload rather than the
  wrapper: for `String` and `Vec<u8>` emptiness is a runtime property, and an empty
  `Dynamic<String>` is a legitimate value to hold before validation, so there is nothing
  for a compile-time check to decide. That does leave one honest gap rather than a
  non-problem: a *statically* zero-sized inner type. `Dynamic<Zst>` constructs where
  `Fixed<Zst>` is now rejected. Guarding it would mean a separate `Sized`-only
  constructor path, since `Dynamic<T: ?Sized>` cannot ask for `size_of::<T>()`, so it is
  left as a documented asymmetry rather than smuggled into this change.

  **Migration:** nothing, unless a `Fixed<[u8; 0]>` was being constructed on purpose. Tests
  that used it as a vehicle for an empty-input decoder case move to the `Vec<u8>` decoders,
  where a zero-length result is representable — which is what this crate's own base32 test
  did.

- **The heap-residue threat model is corrected in four places, all by measurement.** A review
  pass built its own allocator instruments rather than reading the prose, and the documented
  story turned out to be wrong in one direction and incomplete in three.

  **The residue is not unconditional.** `SECURITY.md` said a growth past capacity "allocates a
  new buffer, memcpys the contents, and frees the old buffer". That is what happens when the
  allocator *moves* the buffer. `Vec` asks for a `realloc`, and an allocator that can extend
  the chunk in place does so, copying and abandoning nothing. Measured with the default system
  allocator and no instrumentation: a full 1008-byte buffer grown by 96 — the exact pair
  `check_growth_orphan_retains_secret_vec` uses — extends in place, as do a 1040-byte `String`
  grown by 16, a 4096-byte buffer grown by 65536, and a growth with one allocated neighbour
  immediately behind. On a fragmented heap the same growth moves and the abandoned chunk holds
  the secret. So the exposure is real with a probabilistic trigger. The documentation now says
  so, and says that the byte counts come from an instrument that does not override `realloc`
  and therefore forces the copying path on every growth. That is the right choice for a threat
  model, but it is the worst case rather than the typical one, and `lifecycle_trace_heap.rs`'s
  header no longer claims that an in-place resize "would leave the same residue" — it leaves
  none, because nothing is abandoned: the old bytes are inside the allocation the wrapper still
  owns and still wipes.

  **Shrinking abandons a buffer too.** Framing the weakness as growth past capacity was the
  wrong mental model. `shrink_to_fit` and `shrink_to` reallocate downward and free the old
  block with the secret in it, and truncate-then-shrink is the worst of the family: a pre-sized
  4096-byte buffer truncated to 2048 and then shrunk released its old block holding **4096**
  non-zero bytes, the live prefix and the discarded tail together, while the wrapper went on to
  protect only the smaller replacement. A buffer that never grew can leak its entire contents
  this way. `reserve` is the converse surprise: it abandons the old buffer while writing no
  payload at all. The dangerous-operation list and the README both now say *capacity-changing*
  rather than growing, and name both shrink methods.

  **The bound on the exposure was never stated.** The documentation said what is not covered
  and never said what is. The buffer the wrapper holds after the change is the currently-held
  allocation, so it is zeroized on drop, spare capacity included — measured at 0 non-zero bytes
  of 2016, with a positive control confirming its tail held payload going in. The exposure is
  confined to the abandoned buffers, plural, one per move. `tests/lifecycle_trace_heap.rs`
  already asserted this five times; only the prose was missing it.

  **The recommended remedy leaked.** `SECURITY.md` advised replacing the wrapper with
  `Dynamic::new_with(|v| …)`. That closure starts with an empty `Vec`, so filling it byte by
  byte reallocates its way up and abandons its own intermediate buffers: 1016 secret bytes
  across 7 blocks for a 1008-byte secret. The advice now says to pre-size inside the closure or
  to build the value and use `Dynamic::new`, both of which measured 0. The limitation's scope is
  also widened to name the two routes it omitted: `as_wrapper_mut` on a newtype declared with
  `derive: [IntoWrapper]` or `[WrapperAccess]`, and the `new_with` closure itself.

  **Two more, from an adversarial pass over the safe-growth advice itself.** The
  `std::io::Write` path this section offers as the one place the crate owns the growth needs
  the `std` feature, and `full` does **not** enable `std` — so a consumer building with
  `--features full`, which is what the documentation suggests everywhere else, does not have
  that impl at all and has no safe growth path. Said plainly now. And it is the impl *on the
  wrapper* that is safe, not `Write` in general: `d.expose_secret_mut().write_all(b"…")`
  resolves to the standard library's `impl Write for Vec<u8>`, which grows by
  `extend_from_slice` and abandons the old buffer unwiped. Measured on a 1000-byte secret,
  the wrapper's own `write_all` leaves 0 surviving bytes and the reached-through form leaves
  1000. Two lines that look alike and behave oppositely, so the difference is now documented
  rather than implied.

- **`CloneableSecret`'s docs record a rustc suggestion that would delete the gate.** Calling
  `.clone()` on a *reference* to a wrapper whose inner type lacks the marker, with no target
  annotation, resolves to `<&T as Clone>::clone`. It compiles, and the only diagnostic is the
  warn-by-default `noop_method_call`, whose `help:` proposes adding `#[derive(Clone)]` to
  `Dynamic` — that is, proposes removing the opt-in this crate exists to enforce. Nothing is
  duplicated, so no secret escapes; the call does nothing at all. It is documented because a
  reader who follows rustc's advice dismantles the gate, and because the real error is only
  one receiver away: an owned value, or an annotated target, still reports the unsatisfied
  `CloneableSecret` bound.

  **A fifth correction, to the escape route rather than the weakness.** `SECURITY.md` said a
  custom-allocator-parameterized `Dynamic<T, A>` "currently requires nightly Rust
  (`allocator_api`)". Nightly is needed only for the standard library's own `Vec<T, A>`; the
  `allocator-api2` shim ships a stable `Allocator` trait and its own `Vec<T, A>` and declares
  `rust-version = "1.63"`, so it is within reach of both release lines. Verified rather than
  assumed: a twenty-line zeroize-on-free allocator parameterizing such a `Vec` compiled and ran
  with no nightly features on both rustc 1.70 and current stable, saw the abandoned buffer with
  1008 of 1008 bytes still live, and wiped them before release — read back inside the allocator
  after the wipe and before the inner `deallocate`, which is the only window where that can be
  checked, giving 0.

  Getting this right matters because it moves the obstacle. The reason this crate does not do it
  is not a toolchain channel: implementing such an allocator needs `unsafe impl Allocator` and
  this crate is `#![forbid(unsafe_code)]`, it would add a non-optional dependency to a crate
  that has exactly one, and it would add a type parameter to `Dynamic`, which is API-breaking.
  Those are the real reasons, and they are better ones.

### Removed

- **BREAKING: `fixed_alias!`, `dynamic_alias!`, `fixed_generic_alias!` and
  `dynamic_generic_alias!` are deleted.** Three of the four expanded to a single `type` line
  and a generated doc attribute; `fixed_alias!` added a const-eval guard rejecting `N = 0`.
  What none of them added was a type. Two aliases over one shape were always the same
  nominal type, freely substitutable for each other.

  The problem was never what they expanded to. It was that a macro exported by a crate whose
  pitch is "accidents must not compile" reads as a guarantee, and these guaranteed a name.
  This repository's own README called them "typed newtype wrappers" and "Type-safe wrappers"
  from 0.5.1 until commit `fe93540`, whose message records that downstream users had relied
  on that reading. The measured consequence is in
  `docs/design/secure-gate-requested-newtyping-requirements.md`: a consumer's 34 aliases
  collapsed to 8 real types, with `FileId` (documented "never crosses IPC") and `PublicId`
  (documented "safe to expose via IPC") the same type on adjacent lines, and five distinct
  32-byte cryptographic keys mutually substitutable. Nobody misreads
  `pub type FileId = Dynamic<String>;`.

  With `fixed_newtype!` / `dynamic_newtype!` shipped since rc.8, the alias macros were also
  dominated on every axis. A newtype costs nothing at runtime — `tests/asm_dse_check.rs`
  proves the zeroization stores survive optimization through the extra layer, and under an
  LLVM that folds the two symbols it is byte-identical, though whether the fold happens is
  the toolchain's call and zeroize 1.9 stopped it here — and is strictly safer, so where a
  role exists the newtype
  wins; and where no role exists, one line of ordinary Rust is shorter than the macro call it
  replaces. Keeping both left two same-shaped macros one word apart, differing only in the
  property that matters, which is why the documentation had to carry a "Nominal?" column to
  tell them apart.

  The case *for* aliases is untouched, and rc.9's note on when an alias is the right reach
  still stands word for word: material worth zeroize-on-drop and a redacted `Debug` that has
  no role it could be confused with, where interchangeability with the base type is a feature
  because it crosses into third-party APIs without ceremony. Only the spelling changes. A
  doc comment on the `type` gives the documentation the macro's optional doc-string argument
  used to provide.

  **Migration** is mechanical and one line per alias:

  | Was | Now |
  |---|---|
  | `fixed_alias!(pub X, N);` | `pub type X = Fixed<[u8; N]>;` |
  | `fixed_alias!(pub X, N, "doc");` | `/// doc` above `pub type X = Fixed<[u8; N]>;` |
  | `dynamic_alias!(pub X, T);` | `pub type X = Dynamic<T>;` |
  | `dynamic_alias!(pub X, T, "doc");` | `/// doc` above `pub type X = Dynamic<T>;` |
  | `fixed_generic_alias!(pub X);` | `pub type X<const N: usize> = Fixed<[u8; N]>;` |
  | `dynamic_generic_alias!(pub X);` | `pub type X<T> = Dynamic<T>;` |

  For a tree with many of them, this GNU `sed` run covers every form above, including
  `pub(crate)`, the optional doc string, and an inner type containing a comma. Run the
  doc-string forms first. Out of order nothing is silently wrong, but you get a mess to undo
  by hand: the `fixed_alias!` two-argument pattern ends in `, ([0-9]+)\);` so it cannot match
  a three-argument call at all and leaves the line as a macro invocation, while the
  `dynamic_alias!` one does consume the doc string into the type position and yields
  `Dynamic<String, "doc">`, which fails loudly as `error[E0107]: struct takes 1 generic
  argument but 2 generic arguments were supplied`:

  ```sh
  # Doc-string forms first: the doc becomes an ordinary `///` comment.
  sed -i -E 's#fixed_alias!\((pub(\([^)]*\))? )?([A-Za-z0-9_]+), ([0-9]+), "(.*)"\);#/// \5\n\1type \3 = Fixed<[u8; \4]>;#' $FILES
  sed -i -E 's#dynamic_alias!\((pub(\([^)]*\))? )?([A-Za-z0-9_]+), (.+), "(.*)"\);#/// \5\n\1type \3 = Dynamic<\4>;#' $FILES
  # Then the two-argument forms.
  sed -i -E 's#fixed_alias!\((pub(\([^)]*\))? )?([A-Za-z0-9_]+), ([0-9]+)\);#\1type \3 = Fixed<[u8; \4]>;#' $FILES
  sed -i -E 's#dynamic_alias!\((pub(\([^)]*\))? )?([A-Za-z0-9_]+), (.+)\);#\1type \3 = Dynamic<\4>;#' $FILES
  ```

  Then replace the macro import with `use secure_gate::{Dynamic, Fixed};`. The generic
  aliases are rare enough to convert by hand, per the last two table rows. The `N = 0` guard
  is not lost in the move: `Fixed` now rejects a zero-sized value at construction (above),
  which is what covers the hand-written `type` the macro used to special-case. The last tags
  carrying these macros are `v0.9.0-rc.9` on this line and `v0.8.0-rc.12` on the 0.8 line,
  which receives the same change.

### Testing

- **The zero-size guard is pinned by a `trybuild` case that needed a `pass` fixture to work
  at all.** `trybuild` runs `cargo check` unless the same `TestCases` also holds a `pass`
  case, in which case it runs `cargo build`
  (`trybuild/src/cargo.rs`: `.arg(if project.has_pass { "build" } else { "check" })`). A
  post-monomorphization `const` error is only raised during codegen, so the first version of
  `tests/compile-fail/fixed_zero_size.rs` compiled clean under `check` and the test asserted
  the exact opposite of the truth — it reported "expected test case to fail to compile, but
  it succeeded". `tests/compile-pass/fixed_nonzero_size.rs` is what flips the run into
  `build` mode, and it earns its place twice over: it is also the positive control that the
  guard rejects nothing valid, covering `new`, `new_with`, a generic constructor and a
  `generic`-arm newtype.

  Left for a follow-up with `workflow` scope: `fuzz-miri.yml` still passes
  `--skip fixed_alias_zero_size_compile_fail` for a test that no longer exists. It is a
  no-op either way, because every compile-fail test is `#[cfg(not(miri))]` and so does not
  exist under Miri at all, but the line is stale and should go.

  Two things to know about the snapshot. Only two diagnostics appear for three bad
  constructions, because the third routes through `Fixed::<[u8; 0]>::new` as well and a
  failed constant is reported once. And the snapshot embeds the assertion's line number in
  `src/fixed.rs`, so an edit to that file above the assertion moves it and the snapshot needs
  re-blessing with `TRYBUILD=overwrite cargo test compile_fail` on the pinned toolchain.

- **The DSE guard follows the drop path instead of assuming the glue is inlined.**
  `tests/asm_dse_check.rs` extracted `make_and_drop_fixed`'s body and asserted the
  zero-stores were in it. Whether they are is LLVM's inlining decision, not a
  property of zeroization, and the lockfile refresh to zeroize 1.9 flipped it:
  1.9 replaces the per-element `compiler_fence(SeqCst)` with an `asm!` barrier, a
  body carrying 32 inline-asm blocks is no longer cheap enough to inline, and the
  wrapper collapsed to a single `callq core::ptr::drop_glue::<Fixed<[u8; 32]>>`.
  All four DSE jobs went red reporting `ZEROIZATION REGRESSION DETECTED` against
  assembly whose zeroization was intact — and *stronger* than before, since the
  barrier is now an `asm!` block rather than a compiler fence.

  The assertion now walks from the symbol through the drop glue it calls and
  passes at the first body that still holds its stores, reporting which one it
  used. It steps only into callees whose mangled name identifies them as drop
  glue (`drop_glue` under v0, `drop_in_place` under legacy), so it cannot credit
  an unrelated function's stores, and a negative control — `Fixed`'s `Drop` body
  emptied — still fails. The existing identical-code-folding path is unchanged.

- **Two suites now trace a newtype's whole lifecycle rather than testing its methods one at
  a time.** The existing tests check properties; these follow one secret from creation,
  through reads, mutation and hand-off, to the end of protection, and assert at every
  transition what happened to the material itself. They are split by what can observe a
  secret's storage, because no single instrument reaches both.

  `tests/lifecycle_trace_heap.rs` instruments the allocator, so it can watch a `Dynamic`
  newtype's buffer. Its own `GlobalAlloc` has three modes: the asserting mode
  `tests/heap_zeroize.rs` already used, a pointer-keyed watch mode that records how many
  non-zero bytes a specific block still held at release (so it can assert quantities and
  negatives, which a panicking allocator cannot), and a thread-scoped counting mode for
  "nothing was copied". One aggregate test, as that file's header requires. Covered:
  `dynamic_newtype!` over `String`, over `Vec<u8>`, over the `generic Vec<u32>` arm, and one
  with `derive: [WrapperAccess]`.

  `tests/lifecycle_trace_handoff.rs` is the deliberate complement: no allocator, nothing
  process-global, so it runs in parallel with the rest of the suite and reaches the
  stack-backed shapes the allocator cannot see at all. A `Fixed` newtype never allocates, so
  it traces storage by address identity (every read and write tier is asked for the address
  it reaches, and those addresses are compared as pointers, never dereferenced) and traces
  end-of-life with an inner type that records, inside its own `Zeroize` impl, the value
  present when the wipe happened. 19 tests over six shapes: both size-literal front ends, the
  `generic [i16; 256]` arm, both directional tokens, and a plain `type` alias for the
  contrast.

  What the stack trace establishes that a method test does not: both write tiers mutate the
  wrapper's own storage without moving it; `expose_secret_mut` hands back the same address
  `expose_secret` names, so no forwarding layer is copying the secret into a temporary and
  leaving a second unwiped copy; the README's key-rotation line overwrites the old key where
  it sits; `into_inner` leaves the inert sentinel behind, proved by the wrapper's own `Drop`
  later recording a wipe of the sentinel rather than the secret; `into_wrapper` is a label
  drop and not a protection drop, with the result still `[REDACTED]`; and every shape carries
  real drop glue, so for `[u8; 32]` — which needs no drop of its own — the wipe is scheduled
  rather than merely available.

  **Two doc claims the stack trace contradicted, both now corrected.** First, the `generic`
  arm's stated reason for withholding `SecretLen` was that a length has no meaning for an
  arbitrary `T`. The base wrapper implements `SecretLen for Fixed<[T; N]>` with
  `byte_len() = N * size_of::<T>()`, which is exactly the question the doc said had no
  answer, and `derive: [IntoWrapper]` reaches it in one call. The real reason is the macro's
  field of view — `generic $inner:ty` is one opaque token, so the expansion cannot tell an
  array from a struct and withholds the shape-dependent surface uniformly rather than
  conditionally. Both macros now say that, and the `IntoWrapper` note says that the outbound
  token reopens whatever the base implements for that inner type, the withheld surface
  included. Second, "nothing is copied" on `into_inner` is literally true only for `Dynamic`,
  where the allocation itself is handed over. A `Fixed` stores its secret inline, so
  `mem::replace` must transfer the bytes into the caller's slot; what holds for both is that
  the value is moved and not duplicated-and-kept, because the wrapper's slot receives the
  sentinel. The trait doc, the module example and the `Fixed` comment now draw that
  distinction instead of claiming the stronger thing.

  **CodeQL raised 13 high-severity alerts against the heap trace, and the fix is a better
  message.** Every one was `rust/cleartext-logging` on the same assertion shape: a buffer's
  capacity, read through `with_secret` and therefore secret-derived in the query's model,
  interpolated into an `assert_eq!` failure message. A format argument is a logging sink for
  that query; an operand is not, which is why the assertions comparing *against* a
  `with_secret` result were never flagged. A capacity is a block size rather than secret
  material, so the alerts overstate the exposure — but the interpolation was redundant in the
  first place, because `assert_eq!` prints both operands on failure. The messages now say what
  a mismatch means and let the macro print the numbers, which removes the sink without
  suppressing anything and without losing a byte of diagnostic detail. Confirmed by breaking
  one assertion on purpose: the failure still reports both sizes. The file's header says not to
  put a `with_secret`-derived value back into a format string there.

### Changed

- **`fuzz/Cargo.lock` is tracked.** Fuzzing is part of this crate's assurance story, and
  a crash is only worth finding if it still reproduces later. `arbitrary` decides how a
  stored corpus byte string maps to a generated value, so a minor bump there can change
  what a saved reproducer decodes to and a crash can quietly stop crashing — not because
  the bug was fixed, but because the input now means something else. Pinning the lock
  keeps "this input failed on this tree" durable. The crate's own `Cargo.lock` is tracked
  for the same reason. `target/`, `corpus/`, `artifacts/` and `coverage/` stay ignored:
  those are generated, and the corpus is an input to fuzzing rather than to the build.

- **The repository is a single crate at the root.** With `secure-gate-compat` gone the
  workspace had one member, so `secure-gate-core/` is dissolved: `src/`, `tests/`,
  `benches/` and `fuzz/` move to the root, and the crate's `README.md`, `CHANGELOG.md`
  and `SECURITY.md` become the repository's. Design records move from
  `secure-gate-core/docs/` to `docs/design/`, alongside the existing `docs/audits/` and
  `docs/plans/`. `cargo publish` no longer needs `-p secure-gate`; nothing else about
  the published crate changes.

  The old root `README.md` and `CHANGELOG.md` were workspace-level summaries of a
  workspace that no longer exists. They are superseded by the crate's own, which are the
  ones that ship and the ones docs.rs renders; their content is in git history. The CI
  section from the old root README is carried over.

### Added

- **`Case` on the bech32 encoders — `try_to_bech32`, `try_to_bech32m`, and both
  `_sized::<N>` forms now take `Case::Lower` or `Case::Upper`.** Requested by a
  downstream adopter whose private identity key is a bech32 string in age's uppercase
  form, `AGE-SECRET-KEY-…`; encoders emitted lowercase only, so the value that most
  warranted `EncodedSecret` shipped as a plain unzeroized `String`.

  Uppercasing happens inside the encoder, on the exact-capacity buffer it already owns.
  ASCII case conversion is length-preserving, so it cannot reallocate and the secret is
  never copied. BIP-173 defines the checksum over the lowercase form and accepts either
  pure case, so uppercasing HRP, separator, payload and checksum together stays valid
  and decodable.

  **The parameter's absence elsewhere is the safety property.** `to_base64url` and
  `to_base32` take no `Case`, because there is no legitimate choice: base64url gives
  `a`–`z` and `A`–`Z` distinct meanings, so converting case destroys the value
  (`3q2-7w` → `3Q2-7W` fails to decode), and RFC 4648 §6 base32 is uppercase by
  definition with a decoder that rejects anything else. A caller cannot ask for a
  conversion that would corrupt the value, because there is no parameter to pass.
  `to_hex` / `to_hex_upper` are unchanged: hex decoding is case-insensitive either way,
  so there is no hazard to close, and `to_hex` is the most common call in the crate.

  This replaces the `EncodedSecret::make_ascii_uppercase` / `make_ascii_lowercase` pair
  that briefly existed on this branch and was never published. Those were general over a
  type that deliberately erases which encoder produced it, so they could not check
  anything — and since `EncodedSecret::new` is `pub(crate)`, the only values that type
  can hold are the five encodings this crate emits, two of which corrupt under case
  change. The generality was confined entirely to the set where the operation is
  sometimes wrong, and bought nothing outside it. Documentation was the only guard;
  moving the choice to encode time makes the hazard unrepresentable instead.


### Changed

- **BREAKING: the four bech32 encoders take a `Case`.** `try_to_bech32(hrp)` becomes
  `try_to_bech32(hrp, Case::Lower)`, and likewise for `try_to_bech32m` and both
  `_sized::<N>` forms, on `Fixed`, `Dynamic` and the newtype macros. Every one of these
  call sites is already being edited in this same release: rc.8 returned
  `Result<String, _>` and rc.9 returns `Result<EncodedSecret, _>`, with the
  `*_zeroizing` twins removed. The parameter makes an edit callers are already making
  slightly larger rather than adding a migration of its own.


- **BREAKING: every encoder returns `EncodedSecret`; the `*_zeroizing` variants are
  gone.** `to_hex()`, `to_hex_upper()`, `to_base32()`, `to_base64url()`,
  `try_to_bech32()`, `try_to_bech32m()` and both `_sized` forms now return
  [`EncodedSecret`] instead of `String`. The eight `*_zeroizing` twins are removed: the
  short name now *is* the safe one. **16 encode methods become 8.**

  The old pairing put the leaky variant on the short, obvious name and charged nine
  characters for the safe one — the opposite of every other decision in this crate. It
  also meant the crate shipped a documented path that hands a full second copy of a
  secret to an unwiped `String`, which is what repeated review passes kept flagging.
  Adding `EncodedSecret` alongside it did not make that go away; only deleting it does.

  **Migration:** drop the `_zeroizing` suffix — `to_hex_zeroizing()` becomes `to_hex()`.
  Where you consumed a `String`, read through the deref instead: `&*encoded` is a `&str`,
  which is what `serde_json`, `sqlx`, `rusqlite` and every other driver binds. Call
  `.into_inner()` only when an API demands an owned `String`; that call is now the named,
  greppable moment protection ends.

  `EncodedSecret` has no `Display`, so `format!("{encoded}")` becomes
  `format!("{}", &*encoded)`, and no `PartialEq`, because comparing secret material with
  `==` is variable-time — that is what `ConstantTimeEq` is for.

- **BREAKING: `RevealSecret::into_inner()` returns the plain value, not
  `InnerSecret<T>`.** Protection ends at the call, and the call is the whole hand-off:

  ```rust
  let v: Vec<u8> = secret.into_inner();
  ```

  The old shape was `secret.into_inner().into_zeroizing()`, or a clone through the
  deref. `zeroize` deliberately exposes no way to move a value out of `Zeroizing<T>`, so
  the only route from a `Dynamic<Vec<u8>>` to an owned `Vec<u8>` was three calls and a
  second full copy of the secret, plus a wasted allocation for anything large.

  No copy is made now. The value is moved out with `mem::replace` and an inert
  `SentinelValue` is left to be zeroized in its place — the same mechanism `Fixed` and
  `Dynamic` already used internally, so the bound (`T: SentinelValue`) excludes nothing
  that could reach a secret wrapper in the first place. The returned `T` is an ordinary
  value: protection is maximal right up to the call, and the call ends it. Pinned by a
  test asserting pointer identity, so a future refactor that turns the move back into a
  copy fails.

  **Migration:** write `secret.into_inner()` where you wrote
  `secret.into_inner().into_zeroizing()` or `secret.expose_secret().clone()`. To keep the
  wiping past the hand-off, keep the wrapper, or wrap the value yourself with
  `zeroize::Zeroizing::new(..)`.

- **BREAKING: the default bech32 code length is 1023, not 8191, and `Bech32Large` is
  gone.** `ToBech32` / `FromBech32Str` used a custom checksum whose `CODE_LENGTH` was
  8191 — roughly eight times the length of the bech32 BCH code, which is 1023 in the
  `bech32` crate for both `Bech32` and `Bech32m`. That constant is documented upstream as "how
  long a coded message can be ... for the code to retain its error-correcting
  properties", so 8191 silently gave every caller a checksum stretched past the point
  where it detects anything in particular, while the rustdoc claimed it preserved "full
  checksum validation". The plain methods now use `BECH32_CODE_LENGTH` (1023) on both
  the bech32 and bech32m paths, and anything longer is an explicit
  `_sized::<N>` call. `Bech32Large` is removed; write `Bech32Sized<8191>` if you want
  the old constant, and read that type's guarantee note first.

  **Migration:** a payload over ~630 bytes (3-character HRP) that used to encode now
  returns `Bech32Error::OperationFailed`. Replace `try_to_bech32(hrp)` with
  `try_to_bech32_sized::<N>(hrp)`, and the matching decode with
  `try_from_bech32_sized::<N>(hrp)`, sizing `N` with `bech32_code_length`. Already-encoded
  strings are unaffected: `N` was never part of the encoding, so they decode unchanged
  under any `N` at least as large as the string.

- **Three documented bech32 payload limits were wrong and are corrected.** The bech32
  path advertised "~5 KB (5,115 bytes maximum payload)"; 5,115 bytes does not in fact
  encode at 8191, because the figure counted only the checksum and forgot the HRP and
  the `1` separator. The bech32m path advertised a "standard 90-byte payload limit" and
  "decodes only spec-compliant Bech32m strings", but the stock `Bech32m` code length is
  1023 characters (~630 bytes) and nothing enforced 90 — that cap is a BIP-173 address
  convention which neither the `bech32` crate nor this one imposes. The docs now state
  the real bound, name `bech32_code_length` for computing it, and say plainly that
  staying inside 90 characters for address-shaped data is the caller's responsibility.


### Removed

- **`secure-gate-compat` is deleted.** The `secrecy` v0.8 / v0.10 shim crate was
  experimental, never published to crates.io, and had no known consumers — the one
  downstream tracking this project depends on `secure-gate` alone. It cost more than it
  returned: a disproportionate share of every review, audit and release cycle went to a
  crate nobody could install.

  **Recovering it:** the crate is intact in git history and in both release tags.
  `git checkout v0.9.0-rc.9 -- secure-gate-compat` restores it here;
  `git checkout v0.8.0-rc.12 -- secure-gate-compat` restores the LTS version. Both tags
  are pushed, so this works from any clone. Nothing is lost, only unmaintained.

  Removed with it: the crate's five CI lint rows, its release- and debug-profile test
  steps, its `no_std` cross-build, its Miri and fuzz-quick path filters, and the
  `fuzz-nightly-0.9-compat.yml` workflow. `secure-gate` itself is unchanged — this is a
  workspace and CI change, and the published crate's contents and API are untouched.

  The workspace is now a single member. Only `cargo publish` still needs `-p secure-gate`;
  `check`, `test` and `doc` work bare.

- **BREAKING: `InnerSecret<T>`.** The wrapper `into_inner` used to return. It was a
  newtype over `Zeroizing<T>` whose only distinct behaviour was escaping this crate's own
  no-`Deref` rule, and it made the owned hand-off read as
  `secret.into_inner().into_zeroizing()` — two calls, and a clone for anything you
  actually wanted to own. Its redacted `Debug` was the argument for keeping it, but a
  value the caller has just taken ownership of is past the point where this crate's
  redaction means anything: `format!("{:?}", &*inner)` printed the secret already.

  **Migration:** `into_inner()` hands back the `T` directly. If you want the wiping to
  continue, wrap it yourself: `zeroize::Zeroizing::new(secret.into_inner())`.

- **BREAKING: `AsRef<str>` and `AsRef<[u8]>` on `EncodedSecret`.** The type now has one
  accessor, `Deref<Target = str>`, plus the two named consumers `into_inner` (ends
  zeroization) and `into_zeroizing` (keeps it). `&str` coercion, `&*encoded`, every
  inherent `str` method, and method resolution through the deref all still work. For a
  type whose purpose is making extraction visible, four doors onto the same room was
  three too many.

  **Migration:** one pattern does break. Deref coercion applies at a coercion site but
  does not satisfy a generic bound, so a parameter of `impl AsRef<[u8]>` — `fs::write(path,
  &encoded)` being the common one — no longer accepts an `EncodedSecret`. Pass
  `encoded.as_bytes()`. Reported by a downstream adopter who hit it in two key-writing
  paths; an earlier draft of this entry claimed the `AsRef` impls reached nothing `Deref`
  does, which is wrong for exactly this case.

  **This alone did not close the accidental re-encode.** `encoded.to_hex()` still
  compiled afterwards, because method resolution derefs to `str` and `str: AsRef<[u8]>`
  satisfied the encoder blanket impls — so an already-encoded secret could be encoded a
  second time, taking the encoded text as input (a 32-byte key came back as 124 hex
  characters). A compile-fail test written to pin the fix proved it: *"Expected test
  case to fail to compile, but it succeeded."* The reachability came from `Deref`, and
  dropping `Deref` would take the type's primary accessor with it. What closed it is the
  `EncodableBytes` bound above: `str` does not implement it, so the second encode is a
  compile error, pinned by `encoded_secret_no_reencode`.

- **BREAKING: `SecureEncoding` / `SecureDecoding` marker traits.** Both were empty
  markers with blanket impls over `AsRef<[u8]>` / `AsRef<str>`, and nothing in the crate
  ever bounded on them. The per-format traits (`ToHex`, `ToBase32`, `ToBase64Url`,
  `ToBech32`, `ToBech32m`, `FromHexStr`, `FromBase32Str`, …) were implemented directly
  against `AsRef<[u8]>` / `AsRef<str>`, so the markers gated nothing and enabled nothing
  — despite trait-module docs that claimed they were what "enables" the per-format
  impls. Their only consumer anywhere in the workspace was a single test asserting the
  marker existed.

  Contrast `EncodableBytes` above, which replaced the encoder side of that `AsRef<[u8]>`
  blanket later in this release: it looks like the same shape and is the opposite case,
  because deleting it changes which calls compile.

  **Migration:** delete them from any `use` list; delete any `T: SecureEncoding` /
  `T: SecureDecoding` bound and rely on the per-format trait itself, or on
  `AsRef<[u8]> + EncodableBytes` for encoding and `AsRef<str>` for decoding. No encoding
  or decoding behaviour changes from this removal.

- **BREAKING: `DecodingError`.** A public enum that no function in the crate ever
  produced. There was no `From<HexError>`, no constructor, and no signature returning
  it — its only appearances were the definition, the crate-root re-export, and a block
  of tests that hand-built values to assert the shape of a type nothing emitted. Code
  decoding several formats can define the union it actually wants in the same number of
  lines this removed.

  **Migration:** match the per-format error (`HexError`, `Base32Error`, `Base64Error`,
  `Bech32Error`) each decode call already returns, or declare your own wrapper enum.

- **BREAKING: `Bech32Error::ConversionFailed`.** Unreachable, and documented as such in
  its own rustdoc. All bit conversion happens inside `CheckedHrpstring::new()`; the
  `.byte_iter()` that follows a successful `new()` is infallible, so every call site in
  the crate maps failure to `OperationFailed`. The variant was retained "for forward
  compatibility should a fallible conversion path be introduced" — but every error enum
  here is `#[non_exhaustive]`, which already permits adding a variant in a patch release
  without breaking downstream matches. It was pre-paying a cost the attribute had
  covered. The two `# Errors` doc lists that advertised it (`FromBech32Str`,
  `FromBech32mStr`) named an error those functions could not return; they now fold
  bit-conversion failure into `OperationFailed`, which is where it actually surfaces.

  **Migration:** delete the arm. `#[non_exhaustive]` means your match already has a
  wildcard.

- **BREAKING: the `encoding-bech32m` feature.** Removed outright, not aliased. BIP-173
  and BIP-350 now ship together under `encoding-bech32`.

  The split existed in case the `bech32` crate ever separated the two algorithms. It
  will not: they are two seven-line `impl Checksum` blocks in one file, differing in a
  single constant, under upstream's own comment `// Same as Bech32 except TARGET_RESIDUE
  is different`. `bech32` 0.11 has exactly three features — `alloc`, `std`, `default` —
  and nothing algorithm-level to split along. Both of this crate's features already
  enabled the same `dep:bech32`, so turning one off never removed a line of dependency
  code; it gated only this crate's own module.

  What decided it was the code-length work above making the two genuinely symmetric.
  Before, `encoding-bech32` meant a large non-standard variant and `encoding-bech32m`
  meant the spec — an asymmetry that was a real argument for keeping them apart. They
  are now twins: same shape, same `_sized::<N>` knob, same guarantee boundary, same
  error type, differing in one constant no caller ever sets. Two features that are
  provably parallel, over one dependency, are one feature.

  Cost removed: two CI matrix rows and two entries in the `no_std` feature sweep, on
  every push. `ToBech32m`, `FromBech32mStr`, `try_from_bech32m*` and the `Bech32mSized`
  types are unchanged in every respect except the feature that turns them on.


### Security

- **Bech32 encoding left unwiped partial copies of the secret on the heap.**
  `bech32::encode_lower` builds its output from `String::new()` and grows it by
  reallocation. Each intermediate buffer holds a prefix of the encoded secret and is
  freed **without being wiped**, and no wrapper can reach it afterwards — `zeroize`
  says so itself: *"Ensures the entire capacity of the `Vec` is zeroed. Cannot ensure
  that previous reallocations did not leave values on the heap."* So
  `EncodedSecret`'s `Zeroizing` wiped the final buffer while earlier copies survived.

  Measured on the old code: a 634-byte payload produced a string of len 1025 with
  capacity 2048, and a 1568-byte ML-KEM ciphertext len 2519 with capacity 4096 — each
  a reallocation, each leaving a copy behind. Payloads small enough to land on a
  single allocation were unaffected, which is why this went unnoticed: it appears
  exactly at the age- and KEM-sized inputs the `_sized` methods exist for.

  Both encoders now reserve the exact length up front with `bech32_code_length` and
  drive `bech32`'s iterator chain into it directly, giving one allocation and no
  intermediate copies. (A later commit in this release replaced the original
  `encode_lower_to_fmt` call for the stack-staging reason described below.) Output is byte-identical. Upstream computes the same length at the top of
  `encode_lower_to_fmt` and discards it (`let _ = encoded_length::<Ck>(...)`), so
  there was nothing to reuse.

  This is the same defect class the crate already fixed for `Dynamic`'s `io::Write`
  growth path in rc.8 — the pattern was understood, just not applied here.
  Pinned by `bech32_encode_allocates_exactly_once` and its bech32m twin, which assert
  `capacity() == len()` across nine payload sizes; both fail against the old code.

  **And the stack.** Adversarial review then pointed out that `encode_lower_to_fmt`
  itself stages every output character through a 1 KiB stack array
  (`let mut buf = [0u8; BUF_LENGTH]`) that it never clears, so after the call returned
  the encoded secret was still sitting in that frame. The refuters were right that this
  is `bech32`'s code and outside the crate's heap guarantee — and it was still not
  something to leave a footnote about. Both encoders now bypass `encode_lower_to_fmt`
  and drive the same iterator chain upstream uses (`bytes_to_fes` →
  `with_checksum::<Ck>` → `chars`) directly into the pre-sized `String`. The chain's
  entire state is one pending byte, a bit offset, a borrowed HRP and a `u32` checksum
  midstate — 72 bytes on x86_64, pinned under 96 by
  `encoder_chain_carries_no_staging_buffer` so a reintroduced buffer fails the test —
  and each character goes into `out` as it is
  produced. The `CODE_LENGTH` gate upstream applied through `encoded_length` is
  replicated with `bech32_code_length`, which the tests already prove exact.
  `direct_chain_matches_upstream_encode_lower` (one per checksum) asserts byte-for-byte
  equality with upstream across eight payload sizes, so nothing observable changed
  except what is left on the stack. Upstream's function is still used in unit tests,
  as the equivalence oracle only.


### Fixed

- **BREAKING (bug): `fixed_newtype!` lost BIP-173 decode without `alloc`.** Found by a
  read-only audit of PR #171. `Fixed::try_from_bech32*` is deliberately alloc-free — it
  drains into a stack `Zeroizing<[u8; N]>` — and the macro forwards the bech32m
  constructors accordingly, outside `__sg_if_alloc!`. The bech32 ones were nested
  *inside* the alloc gate along with the `ToBech32` encode impl, so after the feature
  fold a `no_std` newtype could decode BIP-350 and not BIP-173, while `lib.rs` still
  advertised `Fixed::try_from_bech32` as available without `alloc`. CI could not catch
  it: no host job runs `encoding-bech32` without `alloc`, which this release already
  recorded as a known gap. The four constructors now sit outside the gate, matching
  bech32m, and `tests/newtype_nostd.rs::nostd_newtype_decodes_both_checksums` pins all
  eight by name under `--no-default-features --features encoding-bech32` -- including
  the four `_sized` constructors, which are the ones #171 actually dropped and which a
  first version of this test did not name. CI gained a matching matrix row, without
  which the pin only ever ran locally.

- **The ASan job did not instrument the bech32 heap oracles.** It ran
  `--features alloc`, but `check_bech32_hrp_mismatch_materializes_nothing` and the
  bech32 decode-zeroize helpers are `#[cfg(feature = "encoding-bech32")]`, so the very
  tests written for this release's "no extra copies of the secret" claim were compiled
  out of the sanitizer run. Now
  `--features alloc,encoding-hex,encoding-base32,encoding-base64,encoding-bech32`.
  Verified by mutation: reordering the HRP check after `byte_iter().collect()` is
  **not noticed** under the old feature set and **fails** under the new one.

- **The default-path fuzz encodes swallowed an impossible `Err`.** The `_sized` paths
  were changed to `expect` during adversarial review; the three default-path sites
  (`try_to_bech32("fuzz")`, `try_to_bech32("mykey")`, `try_to_bech32m("fuzz")`) kept
  `if let Ok(..)`. All three use valid HRPs and payloads far under the code length, so
  an `Err` can only be a regression. Now `expect`.

- **The newtype macros forwarded the sized bech32 *encoders* and not the *decoders*
  (adversarial review, three lenses independently).** `fixed_newtype!` emitted
  `try_to_bech32{,m}_sized` but none of `try_from_bech32{,m}{,_unchecked}_sized`;
  `dynamic_newtype!` was worse, with a single plain `try_from_bech32` and no
  `_unchecked`, no bech32m decode at all, and no sized variants. So a newtype could emit
  a 900-byte secret at a custom code length and then had no way to read it back except
  decoding into a bare `Fixed`/`Dynamic` and copying into the newtype by hand — an extra
  copy of the secret, on exactly the path the inherent constructors exist to avoid.
  The CHANGELOG for this release claimed the forwarding was complete and tested; both
  claims were false. Four constructors added to `fixed_newtype!`, seven to
  `dynamic_newtype!`, and `newtype_forwards_sized_bech32_decode` round-trips every one
  of them. Named `_sized` on the decode side because the two const parameters mean
  different things: `N` is the byte count the newtype holds, `C` is the string length
  it will accept.

- **`bech32_code_length` panicked in debug and wrapped in release for payloads above
  `usize::MAX / 8`.** The `payload_bytes * 8` was unchecked. Unreachable with real
  memory, but the function is documented as exact and a wrapped result would have
  under-sized an encode buffer. It now computes `⌈8b/5⌉` as `8·(b/5) + ⌈8·(b%5)/5⌉`
  with saturating arithmetic: exact for every result that fits in a `usize`, and
  `usize::MAX` — which every encoder refuses — when it does not. Never smaller than the
  truth, never a panic. `code_length_saturates_instead_of_wrapping` pins both halves.

- **`secure-gate-compat`'s `serde-serialize` / `serde-deserialize` features could not
  build on their own.** Each enabled only the corresponding `secure-gate` feature, never
  this crate's `dep:serde`, while the `#[cfg(feature = "serde-serialize")]` /
  `#[cfg(feature = "serde-deserialize")]` blocks in `src/compat/` name `serde` types
  directly. `cargo check -p secure-gate-compat --no-default-features --features
  serde-serialize` failed with `E0220: associated type 'Ok' not found for 'S'`, and the
  `serde-deserialize` half with `E0433: cannot find module or crate 'serde'`. The
  combinations shipped in CI all passed because `secrecy-compat` happens to pull `serde`
  in alongside them, so nothing exercised either feature alone. Both now list `serde`.
  Cargo's `secure-gate/serde-serialize` names the *dependency's* feature and never the
  same-named one in this crate — the two are independent, which is what the gap was.


### Dependencies

- **`thiserror` removed; `zeroize_derive` moved to `[dev-dependencies]`.** With default
  features the dependency tree was nine crates, seven of which existed only to serve two
  proc macros — it is now two:

  ```
  secure-gate                              secure-gate
  ├── thiserror                     →      └── zeroize
  │   └── thiserror-impl (proc-macro)
  │       ├── proc-macro2 → unicode-ident
  │       ├── quote
  │       └── syn
  └── zeroize
      └── zeroize_derive (proc-macro)
          └── proc-macro2, quote, syn (*)
  ```

  `thiserror` was generating `Display` for 6 enums — 14 fixed strings and 4 messages
  interpolating two `usize` fields — plus 6 `Error` impls, 5 of them empty. Its one
  non-trivial job, the `#[source]` chain, existed only on `DecodingError`, removed
  above. `src/error.rs` now writes both out by hand against `core::error::Error`
  (stable since 1.81, comfortably below the 1.85 MSRV), so `no_std` is unaffected.

  `#[derive(Zeroize)]` appears nowhere in either crate's `src/` — the wrappers use
  `Zeroize` and `ZeroizeOnDrop` as *traits* — and every real use is a bench, test, or
  fuzz target. Enabling the derive feature on the library dependency put a proc macro in
  every downstream build for something no shipped code used. Neither `secrecy` 0.8.0 nor
  0.10.1 enables it either, so `secure-gate-compat`'s `pub use zeroize;` now mirrors
  secrecy's re-export more faithfully than it did; the compat test suite had been
  receiving the derive through feature unification and now asks for it directly.

  A downstream crate that wants `#[derive(Zeroize)]` adds
  `zeroize = { version = "1.8", features = ["zeroize_derive"] }` to its own manifest,
  which it needs anyway to name the macro. Verified across seven core feature
  combinations, clippy `--all-targets` on both crates, the full test and doctest suites,
  and the `thumbv7em-none-eabihf` `no_std` cross-build.


### Testing

- **The allocation oracle is thread-scoped, so harness activity can no longer invent an
  allocation.** `tests/heap_zeroize.rs` counted allocations in a process-global
  `AtomicUsize` gated by a process-global flag, which charged every allocation made by the
  libtest harness thread to the closure under test. For a zero-allocation assertion that
  over-count is *fail-closed*, not fail-open: it cannot hide a real allocation, only invent
  one, so it produces a spurious red rather than a silent pass. It still had to go — one CI
  run reported 4 allocations for `check_bech32_hrp_mismatch_materializes_nothing` against a
  decode path byte-identical to four green runs, and an oracle that fails at random teaches
  people to re-run until green, which retires it as surely as deleting it. Thread-scoping is
  what introduces a real fail-open edge — a thread spawned inside the closure is silently
  uncounted — and `count_allocs` now forbids spawning and nesting for that reason. The counter is now a `const`-initialized `thread_local!` `Cell` pair, so
  only the counting thread's own allocations are attributed; the global flag is kept as an
  outer gate so non-counting threads never touch TLS from inside the allocator. No size
  threshold was added — a threshold would hide real small-allocation regressions. Asserting
  mode (`CHECKING` + `TARGET_SIZE`) is still process-global, so the file still runs as one
  aggregate test.

- **Coverage inventory over the 43 encoder tests deleted by the encoder merge — no
  restoration needed.** The deletions were plain-vs-`*_zeroizing` pairs, and the concern was
  that a real assertion had been deleted alongside the tautologies. Five formats were
  checked against four axes (round-trip encode/decode, redacted `Debug`, `into_inner` yields
  the plain encoding, and a compile-fail pin against re-encoding), then each result was
  handed to an independent agent instructed to refute it. All 20 axes hold and no citation
  was found vacuous, so none of the 43 were restored.

  Two axes are covered *once for the type* rather than five times, which is correct and
  worth stating plainly: every encoder now returns the same `EncodedSecret`, and
  `into_inner` is a `mem::take` on its `String`, so
  `encoded_secret_into_inner_returns_string` covers all five formats through a hex fixture.
  `Debug` redaction is likewise type-level, with bech32 additionally asserting it on its own
  encoder output in `tests/encoding_suite/bech32_sized.rs`. Round-trip and the re-encode pin
  are genuinely per-format: `tests/encoding_suite/{hex,base32,base64,bech32}.rs` and
  `tests/compile-fail/encoded_secret_no_reencode{,_all_formats}.rs`.

- **`into_zeroizing` was only ever tested on the empty string.** The single assertion,
  `assert_eq!(&*protected, "")`, would have passed unchanged if the method had discarded
  the buffer and returned `Zeroizing::default()`. Two tests replace that vacuum:
  `encoded_secret_into_zeroizing_carries_the_content` pins that the returned value holds
  the actual encoding (and that `Zeroizing`'s derived `Debug` still prints it in the clear,
  which is what the method's own docs promise), and `check_into_zeroizing_string_zeroed` in
  `tests/heap_zeroize.rs` observes the buffer being zeroed at deallocation. The second was
  falsified before being kept: swapping `into_zeroizing` for `into_inner` makes it fail at
  byte offset 0, so it distinguishes the two exits rather than passing on both.

- **`tests/encoding_suite/bech32_sized.rs`** covers the code-length API against the
  four invariants it has to hold: `N` never changes the encoding; a string decodes
  under any `N` at least as large as itself and no smaller; bech32 and bech32m stay
  mutually undecodable at every `N` (they differ only in target residue, which a shared
  const-generic checksum could have blurred); and HRP validation, exact length
  reporting, zeroizing output and the BIP-173/350 vectors behave identically on the
  `_sized` path. Includes the exact 633/634-byte boundary at `BECH32_CODE_LENGTH`,
  single-character corruption, truncation and extension, and a deterministic randomized
  stress run over a ladder of seven code lengths. Property tests in
  `proptest_suite/encoding.rs` and the `encoding` fuzz target assert the same
  invariants; `tests/macros_suite/newtype_surface.rs` covers the macro-forwarded sized
  methods in **both** directions — the easiest of the expansion sites to leave out, and
  see the adversarial-review entry below for why the decode half of that sentence was
  false when first written.

- **Adversarial review of the bech32 refactor (41 agents, seven lenses, three refuters
  per finding).** Nine findings survived; the three that were test defects are fixed
  here, the rest under *Fixed*.
  - `randomized_stress_across_code_lengths` had a vacuous invariant. Its ladder was
    64/128/256/1023/1024/2048/4096, but with a 3-character HRP a code length is
    `10 + ⌈8b/5⌉`, and since `gcd(8, 5) = 1` that only ever lands on residues
    `{1, 2, 4, 6, 7} (mod 8)` — never a power of two. So `encoded.len() == N` was
    unreachable on six of seven rungs and the `|| encoded.len() < N` escape took the
    "too-small decoder refuses" assertion out of play. Rungs are now defined by payload
    byte counts (32, 64, 128, 633, 640, 1280, 2560 → code lengths 62, 113, 215, 1023,
    1034, 2058, 4106), case 0 of each rung encodes exactly that many bytes, and a
    counter asserts the boundary branch ran on every rung. Mutating the decoder to
    `N` instead of `N - 1` now fails on the first rung.
  - The claim that the HRP is compared *before* any payload byte is materialized had
    no test that could fail: every existing check observed only `Err(UnexpectedHrp)`,
    which is identical whether the `Vec` was never built or built-then-discarded. A
    refuter proved it by swapping the two statements and watching every test pass.
    `tests/heap_zeroize.rs` gained an allocation-counting mode:
    `check_bech32_hrp_mismatch_materializes_nothing` asserts **zero** heap allocations
    on an HRP mismatch across all six sized decode paths (blanket, `Dynamic`, `Fixed`;
    bech32 and bech32m), with a positive control that a correct `Vec` decode allocates
    and a third check that `Fixed` decodes allocate nothing even on success. The same
    statement swap now fails it with "2 heap allocation(s)".
  - The `encoding` fuzz target's sized round-trip block used `if let Ok(..)` and
    silently skipped an `Err`, although every capped payload (≤ 2048 bytes → 3288
    characters) fits `BIG = 4096`, so an `Err` there can only be an encoder regression.
    It is now an `expect`. Two comments in the same file still described a "90-byte
    payload limit" and "BIP-350 compliance" cap that this release's CHANGELOG says never
    existed; corrected.
  Refuted and worth recording: `capacity() == len()` as proof of a single allocation —
  a refuter mutated the reservation to half the length and the test **failed**, so it is
  stronger than the finder assumed. And a real observation that fell outside the
  refactor: upstream `encode_lower_to_fmt` stages every output character through a 1 KiB
  stack array it never wipes. That is `bech32`'s code, not this crate's, and the stack
  is outside the documented heap-wiping guarantee — but a future release could bypass it
  by driving `bech32`'s iterator primitives directly into the pre-sized `String`.


- **The bech32 test module no longer breaks `--all-targets` without `alloc`.** Its trait
  imports and 38 test `cfg`s named only `encoding-bech32*`, but `ToBech32` and friends
  require `alloc`, so `--no-default-features --features encoding-bech32 --all-targets`
  failed to compile with 32 errors. CI never caught it because every encoding row pairs
  the feature with `alloc` and the no_std job builds `--lib` only.

- **`dse-check.yml` gained path filters and a job timeout.** It was the only push/PR
  workflow in the repo with neither. Unfiltered, any commit touching `main` — a
  changelog line, a README fix — spent four release builds (2 OS × 2 toolchains)
  re-proving assembly that had not changed. It now triggers on the inputs the guard
  actually depends on: `secure-gate-core/src/**` (the zeroize-on-drop paths and
  `src/bin/asm_check.rs`, which the test compiles), `tests/asm_dse_check.rs`, the two
  manifests, `Cargo.lock`, and the workflow file. The weekly cron and
  `workflow_dispatch` are unchanged, so the guard still runs against toolchain drift
  even in a quiet week — which is how the rustc 1.98 `.set` → `=` alias change fixed in
  rc.8 would have been caught regardless. `timeout-minutes: 30` replaces GitHub's
  360-minute default.

- **`ci.yml` gained a rustdoc job — no workflow ran rustdoc at all (#175).** A broken
  intra-doc link in the shipping docs would have reached docs.rs unnoticed; that is how
  eleven of them accumulated in `secure-gate-compat`. The job builds `--no-deps
  --all-features` under `RUSTDOCFLAGS: -D warnings`, matching
  `[package.metadata.docs.rs] all-features = true` — so the *feature set* is the one
  docs.rs builds, rather than the `--features full` the issue sketched, which omits
  `std`. It matches docs.rs in no other respect: not the toolchain, not `--cfg docsrs`.
  `--no-deps` is right anyway, because a docs.rs page documents only the target crate
  and links dependency items out to their own pages. It is separately load-bearing for
  the compat step, where documenting dependencies pulls this crate in under whatever
  feature set compat activates and trips the minimal-build links #175 deliberately
  leaves alone (`Fixed::from_rng` among them). Confirmed that a deliberately broken link fails the
  job and that the tree is clean again once the probe is reverted; `secure-gate` is
  clean on 1.85, 1.97, 1.98 and nightly. The ~92 unresolved links in minimal builds
  (`alloc` alone) stay best-effort and unfixed, as #175 decides, and `README.md` now
  records that policy.

- **The docs.rs nightly step blocks instead of warning.** It was the only step
  reproducing docs.rs's configuration and it was `continue-on-error: true`, so a rename
  of the `doc_cfg` gate would have failed it and merged anyway — breaking docs.rs and
  nothing else. It now fails the build, and drops `-D warnings` to make that safe: a
  removed gate is a hard error and still fails, while a new nightly rustdoc lint is only
  a warning and cannot block an unrelated merge.

- **`secure-gate-compat` gained `serde-serialize` / `serde-deserialize` lint rows.** The
  compat matrix ran only no-features, `secrecy-compat` and `--all-features`. Only
  `secrecy-compat` pulls `serde` in, which is exactly how "neither serde feature compiled
  on its own" survived a full cycle unnoticed.

- **Compat's runtime suites run in debug, not just release.** They were in `test-release`
  only, so the profile where `debug_assertions` and overflow checks are live — and the
  one contributors actually run — had no compat coverage.

- **`fuzz-quick.yml` builds the compat fuzz targets.** Compile-breakage there was caught
  only by the nightly compat workflow (4 jobs × ~50 min), which is how a fuzz crate that
  did not build shipped. `cargo fuzz build` catches that class in about a minute. The
  compat fuzz workflow's path filters also now include the workspace manifests,
  `Cargo.lock` and the workflow file itself, and `fuzz-quick.yml` watches its own path.

- **The MSRV job checks `--all-features --all-targets`.** It ran `cargo +1.85 check`
  with `default` and `full` only — neither implies `std`, and `check` without
  `--all-targets` never compiles test targets. A compat test file had stopped compiling
  on 1.85 while every job stayed green, because CI's `stable` had moved to 1.98, where
  the offending expression is accepted. The added step is the configuration that catches
  it, and the workspace is clean under it today.


- **Payload freedom in the error types is enforced, not just documented.**
  `error.rs` has always promised that errors "never contain payload bytes, HRP
  strings, or other input-derived text". That is a security property: these
  errors are produced while parsing secret material, so a variant that captured
  its input would put decoded secret bytes into a value callers routinely log,
  bubble up with `?`, and format into panic messages. `tests/error_tests.rs` now
  applies `assert_payload_free<T: Copy + 'static>()` to all five error types, in
  both a `#[test]` and a `const _` block so it binds builds that never run the
  suite. `Copy` rejects owned payloads (`String`, `Vec<u8>`, `Box<str>`);
  `'static` rejects payloads borrowed from the input. A size ceiling backs it up
  so a payload cannot hide behind an indirection.

  Mutation-tested in three stages, because the first two proved nothing: adding a
  `String` variant is caught by the existing `#[derive(Copy)]` (E0204), and
  dropping `Copy` to make room is caught by `Display`'s match (E0004) — in both
  the crate fails to build before the test runs. Only the third mutation — drop
  `Copy`, add the payload, and extend `Display` so the crate compiles cleanly —
  isolates the new bound, which fires there with E0277. That is the case the
  derive alone does not cover, and the one a future edit would actually produce.


### CI

- **`release/0.8` is scanned by CodeQL for the first time.** Code scanning ran on
  *default setup*, which analyses the default branch and pull requests into it and
  offers no multi-branch option. Measured against the API: 751 analyses on
  `refs/heads/main`, **zero** referencing `release/0.8` — and pull requests into
  the LTS branch received no CodeQL checks at all, including the one that changed
  191 files across the repository flatten. `.github/workflows/codeql.yml` now
  covers push and pull_request on both branches for both configured languages.
  Migrating required disabling default setup in repository settings, so the
  workflow ships gated on `vars.CODEQL_ADVANCED` — GitHub rejects SARIF from an
  advanced configuration while default setup is enabled, and an ungated workflow
  would have failed every push in between. Rationale and the activation order are
  recorded in `docs/design/ci_cross_branch_coverage.md`.

- **A workflow that runs no jobs now fails instead of reporting success.**
  `audit.yml`, `dse-check.yml` and `fuzz-miri.yml` each split into an event-ref job
  and a cross-ref scheduled job, both gated on `github.event_name`. Every trigger
  they declare currently maps to one of the two — but nothing enforced that. Add a
  trigger without extending an `if:` and both skip, and **a workflow whose jobs all
  skipped reports success**: a green tick for a run that executed nothing, which is
  the failure mode least likely to be noticed. Each now carries a `guard` job that
  reads `toJSON(needs)` and fails when every result is `"skipped"`.

- **`release/0.8` gained the weekly `cargo audit`, DSE and Miri coverage it never
  had (#169).** GitHub raises scheduled events only from the default branch, so a
  `schedule:` block on the LTS branch can never fire; those workflows now matrix
  over both refs from `main`. The cross-ref jobs deliberately carry no dependency
  cache.

### Documentation

- **`docs/nominal_newtypes.md` amended on two points that had gone stale or were too
  broad.** §5.2's decision to stay with `macro_rules!` rested partly on not adding `syn`
  + `quote` to a minimal dependency graph. Half of that no longer holds: both are
  already in the published graph via `serde` → `serde_derive` whenever the `serde`
  feature is on, and `full` enables it — measured with `cargo tree --edges normal`, 6
  hits under `full` and 0 under `--no-default-features`. The decision stands, but on the
  narrower `no_std` ground it was written to protect, and the amendment restates the
  reasons that actually carry it now: the macros work, are covered by tests, and
  rewriting tested generation before 1.0 is churn against real behaviour-drift risk.

  §5.3 recorded "there is no coherence obstacle", which is true for *concrete* impls and
  too broad as stated. A second *blanket* impl keyed on the wrapper trait — the shape
  that would let any newtype inherit the encoder surface — is genuinely **E0119**,
  reproduced standalone. That distinction is the reason per-type forwarding exists at
  all, and it is also why implementing `RevealSecret` on a hand-written newtype buys
  none of the encoders: `to_hex` resolves through the byte-shaped blanket, and a wrapper
  is deliberately not byte-shaped.

- **Zero-length secrets: what is actually guarded, and what is not.** The README implied
  the `N = 0` rejection covered `Fixed`. It does not — the guard is a const-eval check
  inside `fixed_alias!` and nowhere else, so `type Name = Fixed<[u8; 0]>;` written
  directly compiles, as do the generic and dynamic alias macros. Tested end to end rather
  than reasoned about: a zero-length secret then behaves *normally* at runtime — it
  constructs, reports `len() == 0`, still prints `[REDACTED]`, encodes to `""`, compares
  `ct_eq`-equal to any other empty, and drops cleanly. Nothing reports a problem, which
  is what makes it worth writing down: the failure is silent and semantic, not a panic.

  Also records that `Fixed` *could* reject it with a `const` assertion in `new` — a
  post-monomorphization error, confirmed to work — and that such a guard could only ever
  fire on construction, never on declaration. Naming the type without building one
  compiles either way, so no guard placed in the type can make the type unnameable.
  `SECURITY.md` gained the corresponding Best Practices entry, which the README already
  claimed existed.

- **When an alias is the right reach, rather than a weaker newtype.** The docs described
  what aliases *are* and when newtypes are better, but never named the case aliases serve
  well: material worth zeroize-on-drop and a redacted `Debug` that has no role it could be
  confused with. There the alias earns its place — protection plus a self-documenting
  name, interchangeable with its base type so it crosses into third-party APIs without
  ceremony, and no cross-contamination to prevent because nothing else shares its shape
  and meaning. Newtypes remain the answer the moment two same-shaped values mean
  different things.

- **docs.rs now shows which feature each item needs.** `Cargo.toml` has been telling
  docs.rs to build with `--cfg docsrs` for some time, but nothing in the crate read that
  cfg — it enabled a configuration with no effect. `#![cfg_attr(docsrs, feature(doc_cfg))]`
  is what it was for: every feature-gated item now carries an "Available on crate feature
  `…` only" badge, 89 of them across the 173 `cfg(feature)` sites, so a reader no longer
  has to infer from prose why a method is missing from their build. Nightly-only and
  inert everywhere else — nothing sets `docsrs` except docs.rs itself and the CI step
  below, added to guard it. (`doc_auto_cfg`, the obvious spelling, was removed in 1.92
  and merged into `doc_cfg`.) The `docs` job runs that exact configuration on nightly,
  and it is allowed to fail the build: a rename of the gate breaks docs.rs and nothing
  else. It runs without `-D warnings`, so a removed gate (a hard error) still fails
  while nightly lint churn cannot block an unrelated merge.

- **The `full` feature was documented as "Everything".** It omits `std`
  (`["alloc", "rand", "encoding", "ct-eq", "cloneable", "serde"]`), which is deliberate,
  so both the crate docs and the README now say "everything except `std`".

- **`docs/encoded_secret_deref.md` records why the output wrapper derefs.** `EncodedSecret`
  is the one type in this crate that implements `Deref`, which is the exact thing
  `Fixed`/`Dynamic` refuse to do, and the note states the rejected alternative in full:
  drop `Deref`, add `as_str()`, and `encoded.to_string()` stops compiling. It was rejected
  because feeding an encoded copy to APIs that speak `&str` is the type's whole job, and
  because `.to_string()` is a *copy* while `into_inner` is a *move* — the wrapper survives
  the first, still wiping. The residual (a `str` method is quieter than a named exit) is
  handled by sweeping `.to_string()` / `.to_owned()` with the encoding audit, which
  `SECURITY.md` lists. Linked from the `EncodedSecret` module docs; deliberately not added
  to `SECURITY.md`, which stays threat model and audit surfaces.

- **The `into_zeroizing` content test now pins the move, not just the content.** Its message
  claimed the method "must hand over the same bytes, not a fresh String" while asserting only
  string equality, which a cloning implementation would satisfy. It now captures the buffer
  pointer before the call and asserts it is unchanged after, the same way
  `dynamic_into_inner_moves_without_copying` does. Falsified: rewriting `into_zeroizing` to
  clone fails the assertion.

- **Four design-record references pointed at paths that do not exist on docs.rs.** `Cargo.toml`'s
  `include` list ships `src/`, `CHANGELOG.md`, `LICENSE*`, `README.md` and `SECURITY.md` — not
  `docs/`, so a `//! Design record:` header naming a bare `docs/…` path renders in the published
  documentation as a pointer to a file that is not in the crate. The three `docs/nominal_newtypes.md` references in
  `src/macros/` and the new `docs/encoded_secret_deref.md` one are now links to the repository,
  matching how `src/traits/mod.rs` already links `SECURITY.md`. Shipping `docs/` in the crate was
  the alternative and was not taken: it would add ten design records to the package for the
  benefit of four one-line references.

- **`SECURITY.md` now says how to sweep `.to_string()` / `.to_owned()`.** An adversarial
  review of the note above caught it asserting that both were already on the Audit Surfaces
  token list. They were not, and they should not be — they are ordinary `str` methods, so a
  project-wide grep is almost all noise, which is precisely why the claim was wrong in a way
  worth fixing rather than deleting. `SECURITY.md` gains the instruction the note was
  reaching for: sweep them as a second pass over the encoder call sites the token list
  already finds, checking what happens to each returned `EncodedSecret`.

- **Four stale statements corrected after the feature fold and the encoder rewrite.**
  `decoding/bech32.rs` described `encoding-bech32` as "distinct from Bech32m" — false
  since the fold; both checksums ship under it. The `# Errors` lists on the unchecked
  decode paths still named "bit-conversion failure" as a class, which went away with
  `Bech32Error::ConversionFailed`; that case is a string longer than the code length.
  The CHANGELOG still said the encoder writes through `encode_lower_to_fmt`, which a
  later commit in the same PR abandoned over the 1 KiB stack staging buffer. And
  `SECURITY.md` never mentioned the 1023 bound at all; it now states what `_sized`
  costs and how to size `N`.

  Not changed, but worth recording from the same audit: `capacity() == len()` in
  `bech32_encode_allocates_exactly_once` is a canary, not a proof — `with_capacity(n)`
  guarantees only `capacity >= n`, so allocator size-class rounding could mask a
  reallocation. It has real value when it fails (a refuter halved the reservation and it
  went red), and the load-bearing guards are the exact `bech32_code_length` assertion
  and the upstream-equivalence test.

- **`ROADMAP.md` removed; its release-branch table salvaged into `README.md`.** The file
  was stamped "Last updated: March 2026", still listed memory pinning (`mlock` /
  `VirtualLock`) and HSM/TPM escape hatches as "Planned for 0.9.x", and was therefore
  wrong about the release it shipped alongside. The one part worth keeping — the
  `main` (0.9.x / edition 2024 / MSRV 1.85) vs `release/0.8` (LTS / edition 2021 / MSRV
  1.70) table and the backport policy — replaces the two prose lines under
  `README.md` § *Branch support*, where install-time information belongs. The two
  workspace-`README.md` references were dropped with it.

- **`docs/plans/base32_encoding.md` annotated as a historical record.** The plan is kept
  for the reasoning it carries — why Base32 belongs in the crate, the constant-time
  backend survey, the rejected alternatives — but it was written before #158 landed and
  read as live instructions. It now states up front that it shipped in `cf43e69` (PR
  #164), that its line numbers are a snapshot, and that it is not a guide to the current
  tree. The two steps it prescribes for wiring a new format into the `SecureEncoding` /
  `SecureDecoding` `cfg(any(...))` lists are flagged inline as superseded, since those
  markers no longer exist.

- **The `secrecy-compat` feature comment describes what the feature actually does.** It
  claimed to "enable" the `v08` / `v10` shim modules; those carry no `cfg` on it and
  always compile. What it really does is turn on the core features the shims need
  (`alloc`, `cloneable`, `serde-serialize`) plus this crate's `serde` dependency, and gate
  the whole compat test surface — `tests/compat_suite/`, `finding5_regression`,
  `migration_full`, the trybuild cases, and via `dual-compat-test` the side-by-side parity
  tests in `tests/compat_dual/`. The comment now says so, names the crate path correctly
  (`secure_gate_compat::compat::…`, not `secure_gate::compat::…`), and records that the
  feature does *not* switch on this crate's own serde features.

- **`Error` impl availability is stated on each error type, not only in the module
  doc.** A downstream hit this on the 0.8 LTS line, where the impl is `std`-gated
  because `core::error::Error` needs Rust 1.81 and that branch targets 1.70. All
  five types now say the impl is unconditional here and gated there, so code
  building against both lines does not have to infer it.

- **`EncodedSecret::into_inner` documents what it costs at a public API boundary.**
  Returning the `String` from your own public function hands callers a value with
  no zeroize-on-drop and no redacted `Debug`; every later copy — a `format!`, a log
  line, a `Clone`, a `serde` round-trip — is an ordinary heap allocation this crate
  can no longer clear. Returning `EncodedSecret` keeps the protection travelling
  with the value, and it derefs to `str`, so read-only callers need no change.

- **`dynamic_newtype!`'s doc slot takes exactly one string literal.** It is matched
  as `$doc:literal`, so `concat!(...)` does not match. Documented along with
  something worse found while checking it: the failure is reported by the catch-all
  arm as *the inner type* not being one of the shaped types, suggesting you write
  `String` literally — when `String` is already correct and the doc argument is the
  real problem. The `///`-attributes form is documented as the way to write real
  prose.

## [0.9.0-rc.8] - 2026-09-07

### Added

- **`fixed_newtype!` / `dynamic_newtype!` — nominal newtypes over `Fixed` / `Dynamic`
  (#155).** The `*_alias!` macros emit `type` aliases, so two aliases of the same shape
  are the *same* type: an encryption key and a MAC key are both `Fixed<[u8; 32]>`, and
  swapping them at a call site compiles silently. The new macros emit `struct`s instead,
  so the compiler rejects a swapped key role. This is the one class of secret-handling
  defect the alias design cannot see.

  ```rust
  fixed_newtype!(pub EncKey, 32);
  fixed_newtype!(pub MacKey, 32, "HMAC-SHA256 key. Never used for encryption.");

  fn seal(enc: &EncKey, mac: &MacKey) { /* … */ }
  // seal(&mac, &enc) does not compile.
  ```

  Syntax mirrors the alias macros (visibility forms, optional doc string), plus an
  opt-in `derive:` list — `ConstantTimeEq`, `Deserialize`, and the base-access tokens
  described below. Generated types are
  `#[repr(transparent)]` with `#[inline]` delegation — `tests/asm_dse_check.rs` now
  asserts against a newtype symbol and finds LLVM folds it into the plain-wrapper
  symbol (`.set`), i.e. byte-identical machine code. They carry every wrapper
  guarantee: zeroize on drop, `[REDACTED]` `Debug`, access only via `RevealSecret` /
  `RevealSecretMut`, and no `Deref` (so separation is total, not by-value-only).

  **`Clone` and `Serialize` are deliberately not generated.** Neither can be forwarded:
  `Fixed<[u8; N]>: Clone` needs `[u8; N]: CloneableSecret`, which the orphan rule makes
  permanently unimplementable downstream. A generated impl would have to route through
  `with_secret` and rebuild — opting the secret into cloning with no marker impl
  anywhere, spelled in one word inside a macro expansion. Since a generated newtype is
  local to the caller's crate, callers who want it write the impl by hand, where the
  decision is visible and greppable. Asking for either is a compile error carrying the
  reasoning; the hand-written pattern is a doctest on `fixed_newtype!`.

  **Inner types are matched as literal tokens.** `dynamic_newtype!(pub P, String)` and
  `(pub P, Vec<u8>)` get the full API for their shape; anything else requires an
  explicit `generic` marker (`dynamic_newtype!(pub P, generic MyStr)`) and gets the
  reduced surface — no `SecretLen`, no encoders. A bare unrecognised type is a compile
  error naming both options, rather than silently degrading. Macros match tokens, not
  resolved types, and this is true of procedural macros too (they run before type
  resolution), so the fix is to remove the silent path rather than to see through the
  alias.

  **No implicit conversion to or from the base wrapper.** Nothing generates
  `From<Fixed<[u8; N]>>` / `From<Dynamic<T>>` or `Deref`, so an alias-typed value (a
  `dynamic_alias!` that stayed a synonym) cannot flow into a newtype through `.into()`,
  and `&Newtype` never coerces to `&Wrapper`. By default the only path in or out is the
  3-tier access API — a `with_secret` round trip. Base-wrapper access is opt-in per
  newtype and split by direction: `derive: [FromWrapper]` adds `from_wrapper` (a base
  value enters the role), `derive: [IntoWrapper]` adds `as_wrapper`, `as_wrapper_mut`,
  and `into_wrapper` (material leaves toward the base), and `WrapperAccess` is both. In a
  mixed tree the base type is the pool every plain alias lives in, so `FromWrapper` on a
  boundary type accepts all of them (the source never opts in — it is just the base
  type), and `IntoWrapper` on a secret role downgrades it to the least-sensitive alias
  sharing its base. Neither token is the sufficient default more often than it looks.

  Shaped `dynamic_newtype!` constructors take `impl Into<String>` / `impl Into<Vec<u8>>`,
  so `Name::new("literal")` works and a hand-written newtype's call sites need not move.

  Design record: `docs/nominal_newtypes.md`; downstream cross-check against
  `docs/secure-gate-requested-newtyping-requirements.md` in its §8. Pinned by 17
  `trybuild` compile-fail cases including cross-role assignment (E0308), `N = 0`, a
  user-added `Drop` (E0509), the rejected `derive:` options, the absent `.into()` path
  from a base wrapper, the absent `Deref`, directional base access, and per-newtype
  `Serialize` not leaking to siblings.

- **Base32 encoding — `ToBase32` / `FromBase32Str` behind `encoding-base32` (#158).**
  The fifth format beside hex, base64url, bech32 and bech32m: `to_base32()` /
  `to_base32_zeroizing()` and `try_from_base32()`, blanket-implemented for
  `AsRef<[u8]>` and `AsRef<str>`, with `ToBase32` impls on `Fixed<[u8; N]>` and
  `Dynamic<Vec<u8>>`, inherent `Fixed::try_from_base32` / `Dynamic::try_from_base32`
  constructors, and a new `Base32Error` (`InvalidBase32`, `InvalidLength { expected,
  got }`, also reachable as `DecodingError::InvalidBase32`). `fixed_newtype!` and
  `dynamic_newtype!` forward both directions for their byte-shaped arms. The backend
  is the constant-time `base32ct` crate — the RustCrypto sibling of the `base16ct`
  and `base64ct` backends already in the tree.

  **One canonical form: RFC 4648 §6, uppercase, unpadded.** That is the shape
  `otpauth://` key URIs carry TOTP/HOTP shared secrets in (RFC 6238 / RFC 4226), and
  the densest encoding that fits QR alphanumeric mode — a 20-byte seed is 32
  characters where hex needs 40. Decoding is strict: lowercase, mixed case, `=`
  padding, whitespace, and lengths that no unpadded Base32 string can have are
  rejected rather than normalized. There is deliberately no `to_base32_lower()` twin
  of `to_hex_upper()` — `base32ct` has no mixed-case decoder, so a lowercase encoder
  would emit strings this crate could not read back; if lowercase is ever wanted it
  arrives in both directions at once. The one leniency `base32ct` keeps is
  non-canonical trailing bits (`"MZ"` decodes to the same byte as `"MY"`), so
  decoding is not injective and `encode(decode(s)) == s` holds only for
  encoder-produced `s`. That is documented on `FromBase32Str` and pinned by
  `base32_accepts_non_canonical_trailing_bits`, so a future backend change is noticed.

  Included in the `encoding` and `full` meta-features. The traits require `alloc`
  (they return `String` / `Vec<u8>`), but `Fixed::try_from_base32` decodes into a
  `Zeroizing<[u8; N]>` stack buffer and works without it, like every other
  `Fixed::try_from_*`.

### Changed

- **BREAKING (pre-release): `len`/`byte_len`/`is_empty` moved from `RevealSecret`
  to a new `SecretLen` trait; `RevealSecret`/`RevealSecretMut` widened to every
  inner type (#156).** `RevealSecret` was implemented only for `Fixed<[T; N]>`,
  `Dynamic<String>`, and `Dynamic<Vec<T>>` — because it carried `len()`, which a
  generic inner type cannot answer. That narrowness broke the crate's own
  recommended opt-in pattern: the local inner newtype that
  `CloneableSecret`/`SerializableSecret` docs instruct users to define produced a
  secret that could be cloned, serialized, and zeroized but **never read** —
  `Fixed<SessionKey>` had no `with_secret`, no `expose_secret`, nothing.

  `RevealSecret` (access) and `RevealSecretMut` are now implemented for **all**
  `Fixed<T>` / `Dynamic<T>`; length metadata lives in `SecretLen`, implemented
  exactly where a length is meaningful (`Fixed<[T; N]>`, `Dynamic<String>`,
  `Dynamic<Vec<T>>`). The custom-inner-type pattern is now fully usable —
  pinned by `tests/composability.rs`; `SecretLen` staying narrow is pinned by
  `tests/compile-fail/custom_inner_no_len.rs`.

  **Migration:** call sites using `len()`/`byte_len()`/`is_empty()` on a wrapper
  add `use secure_gate::SecretLen;`. No call-site rewrites; on this repo's own
  suite every migration edit was an import line.

- **BREAKING (pre-release): wrapper encoding methods are now trait impls, not
  inherent methods (#156).** `to_hex`, `to_hex_upper`, `to_base64url`,
  `try_to_bech32`, `try_to_bech32m`, and their `_zeroizing` variants on
  `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` are now impls of the existing `ToHex`,
  `ToBase64Url`, `ToBech32`, `ToBech32m` traits (delegating through
  `with_secret`, unchanged behavior and gating). There is no coherence conflict
  with the `AsRef<[u8]>` blanket impls — the wrappers are local and deliberately
  never implement `AsRef<[u8]>`.

  This makes the encoding surface generic: `fn fingerprint<S: ToHex>(s: &S)`
  accepts `Fixed`, `Dynamic`, and any forwarding newtype — impossible with
  inherent methods, which cannot be named as a bound or forwarded generically.
  Decode constructors (`try_from_hex`, `try_from_base64url`,
  `try_from_bech32*`) remain inherent: construction needs `Self`.
  `Dynamic<String>` still has no hex encoding — the
  `dynamic_string_no_hex` compile-fail now imports `ToHex` and proves the impl
  genuinely does not exist, not merely that an import was missing.

  **Migration:** add the format trait import at call sites
  (`use secure_gate::ToHex;` etc.); call syntax is unchanged.

  Design record for both changes: `docs/composability_restructure.md`.
  The same restructure is planned as a backport to the 0.8 line before its
  first stable release, so both lines expose the same trait shape.

### Removed

- **BREAKING: `Display` on `EncodedSecret` (#149).** `{}` on an `EncodedSecret` is now a
  compile error. The type printed `[REDACTED]` for `Debug` and the full encoded secret
  for `Display`, which is the wrong way round for accident-prevention: redacted `Debug`
  teaches a caller that the type is safe to put in a log line, and a transparent
  `Display` on that same type then punishes exactly the callers who checked.
  `tracing::info!("token: {tok}")` and `format!("{tok}")` were the realistic accidents,
  and a missing `Display` is what prevents them.

  **Scope — this closes format strings, not extraction.** `Deref<Target = str>` is
  retained, so `str::to_string()` and `.to_owned()` still yield an ordinary unzeroized
  `String`. Removing `Display` does not change that and was never going to: those are
  named, intentional extraction, and the crate stops there by design (see *Where
  accident-prevention ends*). Do not read this change as making `EncodedSecret`
  copy-proof.

  **Migration:** write `&*encoded` where you previously relied on `Display`.
  `format!("{}", &*encoded)`, `write!(w, "{}", &*encoded)`, and `encoded.as_ref()` all
  work unchanged; `AsRef<str>` and `AsRef<[u8]>` are untouched. Enforced by
  `tests/compile-fail/encoded_secret_no_display.rs`.

### Security

- **`std::io::Write` on `Dynamic<Vec<u8>>` left the secret in the outgoing buffer when
  it grew (#152).** Writing past the current capacity delegated to `Vec::write`, so the
  standard library reallocated: it copied the plaintext into the new allocation and
  handed the **old** one back to the allocator with the secret still in it. Drop later
  wiped only the new buffer, so a drop-time check reported success while a full copy of
  the secret had already been freed — recoverable from a core dump, swap, or a heap
  scrape until the allocator reused the page.

  The docs made this worse rather than flagging it: the impl was described as "a pure
  security improvement", `SECURITY.md` said `Write` "is not an exposure surface", and the
  rustdoc example started from `vec![]` — capacity zero, so the documented happy path was
  the worst case.

  `Write` now grows by hand: it allocates the larger buffer, copies, zeroizes the old one
  (contents *and* spare capacity, via `Vec::zeroize`, which does not free), and only then
  releases it. Growth stays amortized — the new capacity mirrors `Vec`'s doubling — so
  repeated writes remain linear, and the only added cost is the wipe itself. Pre-sizing
  with `Vec::with_capacity` still avoids the copy entirely and is now what the example
  shows.

  **Scope.** This covers the growth `secure-gate` performs. It cannot cover
  `with_secret_mut` / `expose_secret_mut`, which hand out `&mut Vec<T>` / `&mut String`;
  a caller's own `push` / `extend` reallocates outside this crate. That case remains a
  documented limitation, and `SECURITY.md` now separates the two instead of denying both.

  Regression test: `tests/heap_zeroize.rs::check_write_growth_orphan_zeroed` grows a
  *live* wrapper and inspects the freed page at the moment of growth. Every other check
  in that file calls `shrink_to_fit` and only ever examines the allocation Drop releases,
  which is exactly why this went unnoticed. Confirmed to fail before the fix
  (`byte at offset 0 was not zeroed before dealloc`) and pass after, in the
  `--no-default-features --features=std` configuration CI runs.

- **`InnerSecret<T>` did not implement `Clone`, so `inner.clone()` silently returned a
  bare `T` (#146).** With no inherent `Clone`, method resolution autoderefed through
  `Deref<Target = T>` and selected `T::clone`, producing an unprotected `String` /
  `Vec<u8>` / `[u8; N]` that is never zeroized — from a call site that names no
  extraction method and does not appear in an `expose_secret` or `into_inner` grep
  sweep. This was the one place where accident-prevention failed *before* a named exit:
  every other route out of an output wrapper (`*inner`, `.to_string()`, `into_inner()`)
  is something the caller asked for by name. Added
  `impl<T: Zeroize + Clone> Clone for InnerSecret<T>`, which clones the inner
  `Zeroizing<T>` so each clone is independently owned and independently zeroized on
  drop; `inner.clone()` now resolves to `InnerSecret<T>`.

  Deliberately **not** gated on `CloneableSecret`. That marker gates cloning a live
  `Fixed`/`Dynamic`; an `InnerSecret` is already past the named extraction, so gating
  here would buy no protection and would only restore the silent `T::clone`
  fallthrough for inner types lacking the marker. `EncodedSecret` is unaffected — it
  derefs to the unsized `str`, so no fallthrough was ever possible there.

  Source-compatible for callers who bound the result with inference or used it as `T`
  by deref; a caller who explicitly annotated `let x: String = inner.clone();` must now
  write `inner.to_string()` or `(*inner).clone()`.

### Fixed

- **The DSE zeroization guard was silently dead on nightly, and could assert against
  stale assembly on any toolchain** (`tests/asm_dse_check.rs`, #150). The test hardcoded
  `target/release/deps/` as the location of the `--emit=asm` output. Nightly Cargo moved
  intermediate artifacts to `target/release/build/<pkg>/<hash>/out/`, the glob found
  nothing, and the test panicked *before reading any assembly* — so for roughly two and a
  half weeks the nightly half of the DSE matrix was not checking zeroization at all. Both
  nightly jobs (ubuntu and windows) failed on `main` at the unchanged SHA `fb15c3d5`
  starting 2026-08-03; both stable jobs passed. Reproduced locally on
  `rustc 1.100.0-nightly (e71c0f1e3 2026-08-18)`.

  The quieter half of the bug was worse: when an earlier build had left an
  `asm_check*.s` in `deps/`, the glob found that **stale** file and the guard asserted
  against assembly from a different compilation — a pass that proves nothing. This was
  observed directly; the stale file from a `stable` run made the `nightly` run pass until
  it was deleted.

  Fixed by emitting to an explicit path (`--emit=asm=<path>`, a stable rustc CLI form
  that accumulates with the `--emit` flags Cargo passes itself) and deleting that path
  before the build, so the layout is never guessed and a leftover file can never be
  mistaken for the current one. The build now goes into an isolated, wiped target
  directory, because otherwise Cargo may consider the binary fresh — identical flags
  since the last run, or a warm CI cache — skip the compile, and emit nothing. A new
  assertion fails loudly if Cargo reports success but no assembly appears, so the
  degenerate case can no longer masquerade as a pass. Side benefit: the isolated tree
  builds only `asm_check`'s real dependencies rather than the workspace dev-dependencies,
  cutting the test from a full release build to roughly 10 s. Verified on nightly,
  stable, and the pinned 1.85, including back-to-back runs with identical flags.
- **`dynamic_no_deref` compile-fail snapshot mismatched under `--features=std` (#157).**
  Root cause was diagnostic, not semantic: with `std` enabled `Dynamic<Vec<u8>>`
  implements `io::Write`, so rustc appended a ``help: there is a method `by_ref` with a
  similar name`` note to the E0599 for `secret.as_ref()`, and the snapshot (blessed
  without `std`) no longer matched. The `AsRef` probe is now written through the trait
  (`AsRef::<Vec<u8>>::as_ref(&secret)`), which yields E0277 with no similar-name lookup
  — a sharper assertion of the actual property (no `AsRef` impl) and byte-identical
  output across `alloc`, `std`, and `full` on the blessing toolchain.
- **The DSE guard follows both spellings of LLVM's identical-code-folding alias.**
  `tests/asm_dse_check.rs` resolves the `fixed_newtype!` symbol through the alias LLVM
  emits when it folds the newtype into the plain wrapper, but only knew the
  `.set a, b` form. rustc 1.98 (LLVM 22) writes `a = b` instead, so on that toolchain
  the fold looked like a missing symbol and all four DSE jobs failed with "could not
  find 'make_and_drop_newtype' label". Both forms are recognised now; verified on 1.85
  (`.set`) and 1.98 (`=`), ELF and COFF.

### Dependencies

- **`cargo audit` is clean again.** The scheduled audit had been red since 2026-08-10.
  One vulnerability and three warnings, none in code this crate ships:
  `crossbeam-epoch` 0.9.18 → 0.9.21 (RUSTSEC-2026-0204, via `criterion`, dev-only);
  `anyhow` 1.0.102 → 1.0.104 (RUSTSEC-2026-0190, lockfile-only — not in the resolved
  graph); `chacha20` 0.10.0 → 0.10.2 (0.10.0 yanked; via `rand` under the `rand`
  feature). The `bincode` dev-dependency is **removed** (RUSTSEC-2025-0141,
  unmaintained): its only use was one binary-format round-trip of an inner newtype
  that the `serde_json` round-trips in the same suite already cover through the same
  `deserialize_seq` path. Removal is the only fix, not merely the tidier one — the
  advisory has `patched = []` and covers the whole package, so re-adding `bincode`
  at 2.x would trip it again. Docs no longer name `bincode` as the example format.

### Testing

- **Core `--all-features` added to the test and lint matrices.** `full` deliberately
  excludes `std`, so a test gated on `std` together with another feature compiled in
  no CI entry at all. One such test (`newtype.rs::vec_arm_gets_bytes_only_api`,
  `std` + `encoding-hex`) had a missing `io::Read` import that only the 0.8 backport's
  MSRV job — which does run `--all-features` — caught. The new entries compile
  everything, and immediately found a clippy 1.98 `unbuffered_bytes` lint in the
  same test (now reads through `read_to_end`).

- **Compile-fail enforcement that the secret wrappers have no `Deref`/`AsRef`**
  (`tests/compile-fail/fixed_no_deref.rs`, `tests/compile-fail/dynamic_no_deref.rs`, #148).
  This is the crate's load-bearing "no implicit access" claim and it was previously
  asserted only in prose on the core side — `secure-gate-compat` had the equivalent
  guard, core did not. Each case pins three diagnostics: `E0614` for `*secret`, `E0599`
  for `secret.as_ref()`, and `E0308` for deref coercion at a call site wanting the inner
  type. Verified as a real guard by temporarily adding a `Deref` impl to `Fixed` and
  confirming the snapshot mismatches.
- **New `compile-fail` CI job pinned to Rust 1.85 (#148).** The trybuild snapshots assert
  compiler diagnostics, which drift on stable, so every test job skipped them by name —
  and the MSRV job runs `cargo check` only. The result was that no CI job ran any
  compile-fail test: the negative API guarantees were enforced nowhere. The new job runs
  `--test compile_fail_tests` on 1.85, the toolchain the `.stderr` files are blessed
  against, so diagnostics are stable by construction. Skip lists in the stable jobs are
  updated to include the two new test names, per the existing convention.
- **Stable test jobs now skip compile-fail cases by name pattern** (`--skip compile_fail`,
  plus the one legacy name `serializable_secret_misuse`) instead of an enumerated list.
  The enumerated list silently fell out of sync: the eleven compile-fail cases added for
  #155/#156 would have run on stable in every matrix entry and the release-profile job,
  and eight of them mismatch on stable 1.94 (diagnostic drift only). Every core
  compile-fail test is named `*_compile_fail`, so new cases are excluded automatically;
  the 1.85 `compile-fail` job remains the enforcing run.

### Documentation

- **`SecretLen` no longer describes length as safe metadata.** Its `# Security` section
  now distinguishes contents from sensitivity: for variable-length secrets the length can
  narrow a brute-force search or fingerprint an issuer, so it is metadata *about* a secret
  — validate against it, never log or persist it next to an identifier. Also notes that
  `ConstantTimeEq` on variable-length secrets is not length-hiding (`subtle`'s slice
  comparison short-circuits on length mismatch), and that the separate trait import is an
  audit marker rather than a barrier.
- **Scoped every crate-level "no `Deref`" claim to `Fixed`/`Dynamic` (#147).** The slogan had
  drifted across `lib.rs`, `SECURITY.md` (TL;DR bullet and Core Security Model table),
  `traits/mod.rs`, `traits/reveal_secret.rs`, both READMEs, and
  `docs/security_hash_eq.md`, where it read as a crate-wide invariant. It is not: the
  output wrappers `InnerSecret<T>` and `EncodedSecret` implement `Deref` by design, as
  the `lib.rs` type-taxonomy table already stated correctly. Claim now matches code
  everywhere.
- **New "Where accident-prevention ends" section** (`lib.rs` crate docs and
  `SECURITY.md`, following the 3-Tier Access Model). States the boundary explicitly: the
  crate keeps accidents from compiling while a secret is held in `Fixed`/`Dynamic`, and
  that obligation ends at the named extraction (`into_inner`, `expose_secret`,
  `to_*_zeroizing`). Accuracy of documented behavior does not end. Spells out what the
  output wrappers still guarantee (zeroize-on-drop of the buffer they own, redacted
  `Debug`) versus what they do not (tracking copies made through `Deref`).
- **Corrected the false claim that `InnerSecret` is "the only type in this crate that
  derefs to the secret"** (`inner_secret.rs` type doc and `Deref` impl doc, `lib.rs`
  re-export doc). `EncodedSecret` derefs to `str`.
- **Documented that `Debug` redaction does not survive a deref.**
  `format!("{:?}", inner)` prints `[REDACTED]`; `format!("{:?}", &*inner)` prints the
  secret, because redaction is a property of the wrapper and not of `T`.
- **Documented `into_zeroizing()` as a `Debug` downgrade** on both `InnerSecret` and
  `EncodedSecret`. It preserves zeroize-on-drop but not redaction: `zeroize` 1.8/1.9
  derive `Debug` on `Zeroizing<T>`, so `{:?}` on the returned value can print the
  secret. Also noted that this crate does not re-export `zeroize`, so naming the return
  type requires taking a compatible `zeroize` dependency directly.

- **RustCrypto integration example on `Fixed` (#144).** The `Fixed` rustdoc and the
  crate README now show how to run a block cipher *inside* the wrapper —
  `block.with_secret_mut(|b| cipher.decrypt_block(GenericArray::from_mut_slice(b)))` —
  alongside the copy-out shape (`aes::Block::from(*b)`) that type inference nudges you
  toward and that leaves plaintext-equivalent bytes in an unzeroized stack value. The
  mechanism always worked; nothing pointed integrators at it. Both examples are compiled
  doctests rather than `ignore` fences (`aes` joins `[dev-dependencies]`, pinned to the
  0.8 line for the `cipher` 0.4 / `GenericArray` API they use); no library API changed.
  They sit on the `Fixed` struct rather than the `fixed` module header, because `mod
  fixed` is private — its `//!` docs are doctested but never rendered on docs.rs. The
  `with_block_mut` sugar also floated in #144 was deliberately not added: an optional
  `generic-array` dependency and a const-generic-to-typenum mapping to buy what the
  documented pattern already gives.
- **`RevealSecretMut` no longer advertises `len()`/`is_empty()` as coming from
  `RevealSecret`.** They moved to `SecretLen` in the split above; the trait's own rustdoc
  had been left behind.
- **`docs/composability_restructure.md` records the shipped state** — 0.9.0-rc.8 on
  `main` (PR #159, `f2a8f1c`) and 0.8.0-rc.11 on `release/0.8` (PR #160, `a029bb7`) —
  instead of describing in-progress branch work with the backport still pending.

- **The crate page now lists the newtype macros.** The `lib.rs` overview ("What's
  available without `alloc`" and the module tree) named only the alias macros;
  `fixed_newtype!` and `dynamic_newtype!` are listed with a one-line contrast.
- **`SecretLen` has its own crate-level re-export doc.** `pub use traits::{RevealSecret,
  SecretLen};` carried one doc comment for both. Split in two — the tier list stays on
  `RevealSecret`, `SecretLen` gets a short doc of its own — and kept that way because
  rustdoc 1.70, the 0.8 line's MSRV toolchain, ICEs on intra-doc links in a grouped
  `use` re-export; the two lines share this file.

## [0.9.0-rc.7] - 2026-07-06

### Added

- **`Fixed<[u8; N]>` deserialization now accepts byte-string input.** The
  visitor implements `visit_bytes` / `visit_byte_buf` in addition to
  `visit_seq`, so self-describing formats that encode byte arrays as byte
  strings (e.g. CBOR) round-trip. The `deserialize_seq` entry point is
  unchanged, so the wire format for non-self-describing formats (bincode) is
  unaffected. Owned buffers handed over through `visit_byte_buf` are wrapped
  in `Zeroizing` and wiped after the copy.

### Security

- **`no_std` support was advertised but did not exist — now real and CI-verified.**
  The crate never declared `#![no_std]`, so it unconditionally linked `std` and
  failed to build on bare-metal targets despite the `no-std` keyword/category and
  README claims. Fixed end to end: added
  `#![cfg_attr(not(feature = "std"), no_std)]`; disabled the default `std`
  features of `thiserror` and `subtle`; switched `rand` to
  `default-features = false, features = ["sys_rng"]` (with `std_rng` moved to a
  dev-dependency for tests); removed all `String` usage from no-alloc code paths;
  gated `FromBech32Str` / `FromBech32mStr` on `alloc` (matching the other decoding
  traits — their blanket impls always returned `Vec`); and gave the internal
  `asm_check` binary `required-features = ["std"]`. A new CI job cross-builds the
  library for `thumbv7em-none-eabihf` across all no-alloc feature combinations so
  this cannot regress silently. Note: on bare metal, `from_random` additionally
  requires a user-configured `getrandom` backend (documented in lib.rs).
- **`Fixed<[u8; N]>` deserialization could leak a secret prefix through realloc.**
  The `visit_seq` visitor reserved `N` bytes but pushed unboundedly: an input
  sequence with more than `N` elements grew the `Zeroizing<Vec<u8>>` past its
  capacity, and the reallocation freed the old buffer — already holding the first
  `N` secret bytes — without zeroization, before the length check rejected the
  input. Over-length sequences are now rejected *before* the buffer can grow.
  Regression test: `fixed_deserialize_over_length_rejected`.
- **Bech32/Bech32m HRP-checked decoding no longer materializes payload bytes
  before validating the HRP.** `FromBech32Str::try_from_bech32` and
  `FromBech32mStr::try_from_bech32m` (used by `Dynamic::try_from_bech32*`)
  previously decoded the full payload into a plain `Vec<u8>` and *then* compared
  HRPs — on mismatch, the decoded secret was dropped unzeroized. The HRP is now
  validated on the checksum-verified string before a single payload byte is
  produced, matching what `Fixed::try_from_bech32*` already did. Payload
  collection is a single exact-size allocation (`byte_iter()` is an
  `ExactSizeIterator`), so no realloc copies are left behind either.

### Changed (breaking — API stabilization ahead of v0.9.0)

- **Error enums are build-invariant, heap-free, `Copy`, and `#[non_exhaustive]`.**
  Previously, `FromSliceError`, `HexError`, `Base64Error`, `Bech32Error`, and
  `DecodingError` changed *shape* between debug and release builds
  (`cfg(debug_assertions)`-gated variants) — downstream code matching
  `InvalidLength { expected, got }` compiled in dev and broke under `--release`.
  Now, in every build profile:
  - `InvalidLength { expected: usize, got: usize }` always carries both lengths
    (lengths are public protocol parameters; `FromSliceError`'s field `actual`
    was renamed to `got` for consistency).
  - `Bech32Error::UnexpectedHrp` and `DecodingError::InvalidEncoding` are
    fieldless — input-derived strings (received HRPs, hint text) are never
    captured, in any build. This also removes every `String` from the error
    types, making them `Copy` and `no_std`-clean.
  - All five enums and their struct variants are `#[non_exhaustive]`: variants
    and fields can be added without a semver-major bump; downstream matches need
    a wildcard arm, and length-mismatch errors can no longer be constructed
    outside the crate.
- **`RevealSecret::into_inner` bound changed from `Default` to the new
  `SentinelValue` trait — now usable for `Fixed<[u8; N]>` with `N > 32`.**
  The previous `Self::Inner: Default` bound silently made `into_inner`
  uncallable for arrays longer than 32 elements (std's `Default` limit), which
  covers common sizes such as 64-byte Ed25519 expanded keys and HMAC-SHA512
  keys — contradicting the trait docs. `SentinelValue` (exported at the crate
  root) provides the inert placeholder left behind after extraction and is
  implemented for `[T; N]` (any `N`, `T: Default`), `String`, and `Vec<T>`;
  downstream crates can implement it for custom inner types. Regression test:
  `fixed_into_inner_beyond_default_limit`.

### Documentation

- **Marker traits (`CloneableSecret`, `SerializableSecret`): documented the
  orphan-rule consequence.** Downstream crates cannot implement these markers
  for foreign types (`String`, `Vec<u8>`, `[u8; N]`), so the `cloneable` /
  `serde-serialize` features only apply to local newtype inner types. The trait
  and re-export docs now state this explicitly, explain why it is intentional
  (pre-implementing the markers for std containers would silently opt in every
  wrapped secret in a dependency graph), and show the newtype pattern.
- `SECURITY.md`: rewrote the error-metadata section for the build-invariant
  design; documented the serde over-length guard, the HRP-before-decode
  ordering, and the CI-verified `no_std` claim.
- **Inherent Rust memory-residue limitations consolidated** — README and
  `SECURITY.md` now document allocator realloc residue, `Dynamic::into_inner`
  post-transfer mutations, and process/OS mitigations (zero-on-dealloc
  allocators, Linux `init_on_free=1`, core dumps, encrypted swap) in one
  place; Finding 2 rustdoc cross-links updated accordingly.
- **Alias macros (`fixed_alias!`, `dynamic_alias!`)** — rustdoc now states they
  are type aliases, not distinct newtypes (no extra type safety vs. a manual
  `type` alias).
- **`#[must_use]`** on selected APIs so ignored `Result`s and secret wrappers
  trigger rustc warnings.

## [0.9.0-rc.6] - 2026-05-10

### Security

- **Finding 1 — `Dynamic::new_with` closure-panic leak (HIGH).** The intermediate
  buffer used by `Dynamic::<Vec<u8>>::new_with` and `Dynamic::<String>::new_with`
  is now wrapped in `Zeroizing` for the entire lifetime of the closure. A closure
  that wrote secret bytes and then panicked previously dropped a plain `Vec<u8>` /
  `String` during unwind, leaking those bytes to the heap. The fix routes through
  the existing `from_protected_bytes` swap pattern (newly added for `Dynamic<String>`
  and the `cfg` gate removed for `Dynamic<Vec<u8>>`). New regression tests
  (`check_new_with_panic_zeroed_vec` / `_string`) in `tests/heap_zeroize.rs`
  verify the buffer is zeroed via the existing `ProxyAllocator` panic-mode hook.
- **Finding 2 — `with_secret_mut` realloc threat-model gap (MEDIUM, docs-only).**
  `SECURITY.md` now documents that capacity-changing mutations through
  `with_secret_mut` / `expose_secret_mut` on `Dynamic<Vec<T>>` /
  `Dynamic<String>` cause `Vec` / `String` to free the *previous* buffer
  through the standard allocator without zeroization. Added concrete
  guidance: pre-allocate to max needed size, prefer `Fixed<[u8; N]>` for
  known-size secrets, or replace the wrapper rather than mutate in place.
  This is a fundamental limitation of standard-library collections shared
  across the ecosystem; `Fixed<T>` is exempt.
- **Finding 3 — `deserialize_with_limit` zeroization-scope misclaim (MEDIUM,
  docs-only).** The rustdoc on `Dynamic::<Vec<u8>>::deserialize_with_limit` and
  `Dynamic::<String>::deserialize_with_limit` previously suggested the
  `Zeroizing` guarantee covered the full deserialize path. It does not — only
  the post-deserialize buffer is protected; partial bytes accumulated by the
  upstream visitor on error paths are owned by the visitor and dropped as
  plain `Vec<u8>` / `String`. Docstrings now describe the zeroization
  boundary precisely; no behavior change.
- **Finding 4 — DSE workflow coverage gaps (LOW, CI-only).** The DSE
  zeroization-check workflow no longer uses `paths:` filters, so edits to
  the test or workflow itself trigger the check on every PR. The matrix now
  includes `windows-latest` (which exercises the Intel-syntax branch of the
  asm-grep test); macOS is not in the matrix because `macos-latest` is
  ARM64 and would silently skip the `cfg(target_arch = "x86_64")`-gated
  test.

### Breaking

- **`RevealSecret::len()` now returns element count.** Previously all impls returned
  `n_elements * size_of::<T>()` (bytes), which is correct only for `T = u8` and
  violates Rust's universal `len()` = element-count contract (`Vec::len`,
  `slice::len`, etc.). Fixed impls now return element count (`inner.len()` for
  `Dynamic<Vec<T>>`, `N` for `Fixed<[T; N]>`). A new provided method
  `RevealSecret::byte_len()` returns the byte size and is overridden for multi-byte
  element types. **Behavior is unchanged** for the common cases `Dynamic<Vec<u8>>`,
  `Dynamic<String>`, and `Fixed<[u8; N]>`.

### Fixed

- **`secure-gate-compat` keyword count.** Dropped `"no-std"` from `Cargo.toml`
  keywords (crates.io rejects more than 5).
- **MSRV documentation corrected.** `README.md` and `ROADMAP.md` incorrectly
  stated `release/0.8` MSRV as 1.75; corrected to 1.70.
- **`#![forbid(unsafe_code)]` scope clarified.** `SECURITY.md` previously said
  "enforced unconditionally"; updated to "enforced in the library crate" to
  reflect that the binary crate `src/bin/asm_check.rs` uses
  `#[unsafe(no_mangle)]` (Rust 2024 syntax), which is unrelated to the
  library's guarantee.
- **Trybuild snapshots refreshed for rustc 1.85.1 diagnostic drift**
  (`tests/compile-fail/fixed_alias_zero_size.stderr`,
  `tests/compile-fail/serializable_secret_misuse.stderr`) — rustc 1.85.0 →
  1.85.1 reformatted the `E0080` "evaluation of constant value" headline and
  collapsed the `E0277` `help:` blocks for trait-impl pointers into single
  inline `= help:` notes. Snapshots regenerated against 1.85.1 so
  `cargo test --all-features --workspace` passes on the pinned toolchain
  without needing `TRYBUILD=overwrite`. Stable CI continues to skip these
  two cases (see prior entry under [0.9.0-rc.4] CI).

### Documentation

- **`RevealSecret` type-erasure stance clarified (design note).** `Box<dyn
  RevealSecret<...>>` / `Box<dyn RevealSecretMut<...>>` are intentionally not
  supported: the scoped APIs (`with_secret` / `with_secret_mut`) are generic and
  therefore not dyn-compatible. The design decision is to keep scoped access as
  the default tier — it structurally bounds the exposure window and keeps
  `expose_secret*` calls rare and grep-auditable. A companion dyn-erased trait
  (e.g. `DynRevealSecret` using `&mut dyn FnMut`) is deferred until concrete
  type-erasure demand (plugin registries, heterogeneous secret stores) justifies
  the ergonomic and performance trade-offs (`FnOnce` → `FnMut`, no direct return
  value, dynamic dispatch overhead).

## [0.9.0-rc.5] - 2026-04-03

### Documentation

- **README security audit warning** — `secure-gate-core/README.md` now includes a prominent warning that the library has not yet undergone an independent security audit; caution note upgraded to a warning-level callout.
- **README content refreshed** — security model section rewritten for clarity; explicit access requirements and timing-safe equality implementation better described.

## [0.9.0-rc.4] - 2026-03-30

### Added

- **`EncodedSecret` newtype** (`src/traits/revealed_secrets/encoded_secret.rs`, `alloc` feature) — wraps `zeroize::Zeroizing<String>` with redacted `Debug` (`[REDACTED]`), `Deref<Target=str>`, `AsRef<str>`, `AsRef<[u8]>`, `Display`, `into_inner() -> String`, and `into_zeroizing() -> Zeroizing<String>`. Returned by the new zeroizing encoding methods to preserve the zeroization guarantee for sensitive encoded output. Available as `secure_gate::EncodedSecret`.

- **Zeroizing encoding variants** on `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` — `to_hex_zeroizing`, `to_hex_upper_zeroizing`, `to_base64url_zeroizing`, `try_to_bech32_zeroizing`, `try_to_bech32m_zeroizing` — return `EncodedSecret` (or `Result<EncodedSecret, _>`) to maintain the zeroization contract when the encoded form is still sensitive. Plain `to_*()` methods are unchanged for public encodings.

- **Trait-level `_zeroizing` encoding APIs** on existing encoding traits — added `to_hex_zeroizing` / `to_hex_upper_zeroizing` to `ToHex`, `to_base64url_zeroizing` to `ToBase64Url`, `try_to_bech32_zeroizing` to `ToBech32`, and `try_to_bech32m_zeroizing` to `ToBech32m`. This keeps existing trait imports while allowing callers to opt into `EncodedSecret`-returning paths directly from trait methods.

- **Wrapper delegation alignment** for `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` zeroizing helpers — inherent `*_zeroizing` methods now delegate through `with_secret(...)` to trait-level implementations, mirroring the non-zeroizing flow and removing duplicated conversion logic.

- **`InnerSecret<T>` return type for `RevealSecret::into_inner`** (`src/traits/reveal_secret.rs`, `src/fixed.rs`, `src/dynamic.rs`) — `into_inner` now returns `InnerSecret<Self::Inner>` (wrapping `Zeroizing<T>`) to preserve automatic zeroization on drop **and** restore redacted `Debug` (`[REDACTED]`) after ownership transfer. Implemented for `Fixed<[T; N]>`, `Dynamic<String>`, and `Dynamic<Vec<T>>`.
  `InnerSecret::into_zeroizing()` is available as an explicit interoperability escape hatch.

- **Expanded zeroizing test coverage** — added comprehensive tests for trait-level and wrapper-level zeroizing encoding paths across hex/base64/bech32/bech32m, including parity against non-zeroizing outputs, invalid HRP/error paths, oversize bech32m payload handling, redacted `Debug`, and edge cases (empty/all-zero/single-byte payloads).

- **`revealed_secrets_suite` integration tests** — moved `EncodedSecret` tests under `tests/revealed_secrets_suite/encoded_secret.rs`, added dedicated `InnerSecret` tests under `tests/revealed_secrets_suite/inner_secret.rs`, and wired the suite into `tests/integration.rs` to ensure both revealed-secret wrappers are exercised in the directory-based integration binary.

- **Expanded test coverage for encoding edge cases, Dynamic conversions, and serde round-trips** — added tests for `Dynamic<T>` `From<Box<T>>` / `From<T>` impls, `ConstantTimeEq` for `String` (unit + wrapper-level), serde wrapper round-trip for `Fixed<[u8;N]>` / `Dynamic<Vec<u8>>` / `Dynamic<String>`, `deserialize_with_limit` boundary conditions, compile-fail guard for `Dynamic<String>` encoding methods, and `DecodingError` source chain coverage. Also added edge-case tests for `Fixed` encoding decoders covering empty input, single-byte, invalid chars, padding, checksum errors, length mismatches, HRP case-insensitivity, and cross-variant rejection.

- **Encoding backends replaced with RustCrypto constant-time crates** — `hex` and `base64`
  dependencies removed. Replaced by `base16ct` (hex) and `base64ct` (base64url), which
  provide portable constant-time encoding and decoding with no transitive dependencies and
  full `no_std` / no-alloc support.
  - `to_hex()` / `to_hex_upper()` now use `base16ct::lower/upper::encode_string`
  - `to_base64url()` now uses `base64ct::Base64UrlUnpadded::encode_string`
  - Encoding output is identical (same alphabet, same padding behavior)

- **No-alloc decoding for `Fixed<[u8; N]>`** — `Fixed::try_from_hex`,
  `Fixed::try_from_base64url`, `Fixed::try_from_bech32`, `Fixed::try_from_bech32m`
  now work without the `alloc` feature by decoding directly into a stack-allocated
  `Zeroizing<[u8; N]>` buffer. No heap allocation occurs on this path.
  The `alloc` path (heap-decoded `Vec<u8>` → copy) is preserved when `alloc` is enabled.
  The blanket traits (`FromHexStr`, `FromBase64UrlStr`, `FromBech32Str`, `FromBech32mStr`)
  remain `alloc`-only as they return `Vec<u8>`.

- **`encoding-hex` and `encoding-base64` no longer require `alloc`** — features can now be
  enabled on `no_std` + no-alloc targets. `encoding-bech32` and `encoding-bech32m` similarly
  decoupled. Encoding traits (`ToHex`, `ToBase64Url`, `ToBech32`, `ToBech32m`) still require
  `alloc` (they return `String`), but decoding into `Fixed<[u8; N]>` is fully no-alloc.

- **`EncodedSecret::Display` doc note** — added warning that `Display` outputs the encoded
  secret content (unlike `Debug` which prints `[REDACTED]`). Avoid logging with `{}` in
  production — prefer `Debug` for diagnostic output.

- **`.editorconfig` and `.gitattributes`** — added project-wide editor configuration and line-ending normalization rules to ensure consistent formatting across contributors and platforms.

### Changed

- **`ct-eq` feature gate added for `RevealSecret` in `Dynamic`** (`src/dynamic.rs`) — `expose_secret()` usage in `Dynamic` now compiles only when the `ct-eq` feature is enabled, aligning the feature-gate boundary with `Fixed`.

- **Workspace refactored for v0.9** — `secure-gate-core` is now the minimal auditable foundation (published as `secure-gate`); the `secrecy-compat` layer has been extracted into a separate `secure-gate-compat` crate. This reduces the security blast radius and allows the crates to evolve independently. `ZERO_COST_WRAPPERS.md` removed (content integrated into rustdoc). MSRV raised to 1.85.

- **`ConstantTimeEq` impls now route through `expose_secret()`** (`src/fixed.rs`, `src/dynamic.rs`) — `Fixed` and `Dynamic` `ConstantTimeEq` implementations previously accessed `.inner` directly, bypassing the `RevealSecret` trait. They now call `expose_secret()` with a `Self: RevealSecret<Inner = T>` bound, making the "explicit access only via RevealSecret" guarantee honest for external-facing constant-time comparisons. `Clone` and `Serialize` intentionally retain direct `.inner` access to support custom wrapped types that implement `CloneableSecret`/`SerializableSecret` without `RevealSecret`.

- **`RevealSecret` access claim scoped to callers** — documentation reworded from "explicit access only via RevealSecret" to accurately scope the guarantee to external consumers, since internal impls like `Clone` and `Serialize` necessarily access `.inner` directly.

- **`RevealSecret::into_inner` bound documentation corrected** — required bound is `Self::Inner: Sized + Default + Zeroize` (not just `Sized + Default`).

- **Trybuild snapshot baseline pinned to Rust 1.85 for local/dev runs** (`tests/compile-fail/*.stderr`) — restored `fixed_alias_zero_size.stderr` and `serializable_secret_misuse.stderr` to the 1.85 diagnostic format so `cargo +1.85 test --all-features` passes consistently on the declared toolchain.

- **`SecretSlice<S>::clone()` compatibility internals simplified** (`src/compat/v10.rs`) — replaced `Vec::from(&*self.inner_secret)` with `self.inner_secret.as_ref().to_vec()` to keep identical behavior while reducing false positives from static analyzers that misclassify the former as a cleartext logging sink.

### Documentation

- **Comprehensive rustdoc overhaul** — rewrote and expanded documentation for all public types and traits: crate-level usage guide, `Fixed<T>` and `Dynamic<T>` security models, `RevealSecret`/`RevealSecretMut`, `CloneableSecret`, `ConstantTimeEq`, encoding traits (`ToHex`, `FromHexStr`, `ToBase64Url`, `FromBase64UrlStr`, `ToBech32`, `FromBech32Str`, `ToBech32m`, `FromBech32mStr`), decoding traits, revealed secret wrappers (`EncodedSecret`, `InnerSecret`), error types, and alias macros. Each item now includes import paths, security invariants, cross-references, and usage examples.

- **Module-level re-export notes** — added documentation noting that key traits and types are re-exported from the crate root for convenience.

- **README.md** — refined security model section to clarify explicit access requirements and timing-safe equality implementation.

- **SECURITY.md** — clarified security model regarding explicit exposure and timing safety.

### Fixed

- **CI: `-p secure-gate-core` → `-p secure-gate`** (`.github/workflows/ci.yml`) — all `cargo` commands referenced the directory name `secure-gate-core` instead of the package name `secure-gate`, causing every CI job to fail with "did not match any packages".

- **CI: encoding test matrix now includes `alloc`** — encoding traits return `String` (requires `alloc`) and integration tests import them, so `--features=encoding` without `alloc` failed to compile. All encoding CI entries now include `alloc`.

- **CI: compat lint matrix uses correct features** — the `secure-gate-compat` lint entries referenced `rand` and `full` features that don't exist in the compat crate. Replaced with `secrecy-compat` and `--all-features`.

- **Bech32/Bech32m in-crate test modules gated on `alloc`** (`src/traits/encoding/bech32.rs`, `src/traits/encoding/bech32m.rs`) — test modules used `bech32::decode` and `bech32::encode_lower` which require bech32's `alloc` feature. Added `feature = "alloc"` to the `#[cfg]` gate.

- **Bech32 integration test `Fixed` import scoped to both bech32 features** (`tests/encoding_suite/bech32.rs`) — `Fixed` was imported only under `encoding-bech32`, but bech32m tests also use it. Import now gated on `any(encoding-bech32, encoding-bech32m)`.

- **Fuzz crate missing `secure-gate` dependency** (`fuzz/Cargo.toml`) — feature forwarding (`secure-gate/cloneable`, etc.) referenced `secure-gate` but no such dependency was declared. Added `secure-gate = { path = "..", default-features = false, features = ["alloc"] }`.

### CI

- **Stable CI test matrix now skips two toolchain-sensitive trybuild cases** (`.github/workflows/ci.yml`) — `fixed_alias_zero_size_compile_fail` and `serializable_secret_misuse` are excluded from the stable `cargo test --tests ...` step to avoid false failures from rustc diagnostic drift across stable releases.

## [0.9.0-rc.3] - 2026-03-26

### Added

- **`Fixed::new_with` constructor** (`src/fixed.rs`) — closure-based constructor that writes directly into the wrapper's storage via `FnOnce(&mut [u8; N])`, eliminating the intermediate stack copy present in `new(value)`. All library-internal construction paths updated to use it: `TryFrom<&[u8]>`, `try_from_hex`, `try_from_base64url`, `try_from_bech32*`, `from_random`, `from_rng`, and the serde `visit_seq` deserializer. `new(value)` is unchanged and remains the ergonomic default.
- **`Dynamic::new_with` on `Dynamic<Vec<u8>>` and `Dynamic<String>`** (`src/dynamic.rs`) — closure-based constructor for API uniformity with `Fixed::new_with`. Secret bytes are already heap-allocated in `Dynamic`; this method provides a consistent construction idiom across the crate. Internal decode paths (`from_protected_bytes` + `mem::swap`) are unchanged.
- **`secrecy-compat` feature flag** (`Cargo.toml`) — opt-in compatibility shim for teams migrating from `secrecy` without rewriting call sites immediately. Enables `secure_gate::compat` and keeps native secure-gate APIs unchanged.
- **Dual-version secrecy compatibility modules** (`src/compat/`) — added `compat::v10` (secrecy 0.10.1-style `SecretBox<S>`, `SecretString`, `SecretSlice`) and `compat::v08` (secrecy 0.8.0-style `Secret<S>`, `SecretString`, `SecretVec`, `SecretBox`, `DebugSecret`), including API-level docs and migration tables.
- **Shared secrecy trait surface + bridges** (`src/compat/mod.rs`) — added `ExposeSecret`, `ExposeSecretMut`, `CloneableSecret`, optional `SerializableSecret`, and `zeroize` re-export to mirror secrecy imports; also added bridge impls so native `Dynamic<String>`, `Dynamic<Vec<T>>`, and `Fixed<[T; N]>` satisfy compat traits for incremental migration.
- **Conversion paths between compat and native wrappers** (`src/compat/v10.rs`, `src/compat/v08.rs`) — added `From` conversions to move gradually from secrecy-shaped types to `Dynamic<T>` / `Fixed<[T; N]>` and back for common string/vector cases.
- **Exhaustive `secrecy-compat` migration test suite** (`tests/compat_suite/`) — restructured and massively expanded the compat test coverage into a directory-based suite integrated into `tests/integration.rs`. Replaces the two flat test files with five focused sub-modules: `v08` (smoke tests), `v10` (smoke tests), `round_trip` (exhaustive v08↔Dynamic↔v10↔Fixed cross-type conversions with ct_eq checks), `edge_cases` (ZST arrays, large payloads ≥1 MiB, empty collections, non-u8 element types, custom Zeroize-only types, clone independence, move semantics), and `examples` (canonical copy-paste migration guide with 14 self-documenting patterns).
- **Real-world migration integration test** (`tests/migration_full.rs`) — standalone harness-free binary that runs five migration stages (v08 compat, v10 compat, native types, cross-version chain, realistic application struct), prints "Migration validated ✓" on success. Run with `cargo test --test migration_full --features secrecy-compat`.
- **Property-based compat tests** (`tests/proptest_suite/proptest_compat.rs`) — proptest suite for the compat layer: value identity, Debug invariant, clone independence, and (when `ct-eq` is active) ct_eq agreement across all round-trip combinations.
- **Compile-fail enforcement for compat explicit-access semantics** (`tests/compile-fail/compat_*.rs`) — three new trybuild tests proving that `Secret<T>` has no `Deref` (E0614), no `AsRef<str>` (E0277), and that `Debug` requires `DebugSecret` opt-in (E0277); gated on `secrecy-compat` feature.
- **Fuzz targets for compat layer** (`fuzz/fuzz_targets/compat_v08.rs`, `fuzz/fuzz_targets/compat_v10.rs`) — libfuzzer targets covering all round-trip paths, value identity, Debug invariants, and mutable access for both compat generations. Added to CI fuzz matrix.
- **`from_rng` constructor** (`Fixed<[u8; N]>` and `Dynamic<Vec<u8>>`, `rand` feature) — fills with bytes from any caller-supplied `TryRng + TryCryptoRng`, returning `Result<Self, R::Error>`; useful for seeded/deterministic RNGs in tests.
- **`dual-compat-test` feature + dual-parity test suite** (`tests/compat_dual/`) — new opt-in feature that runs identical test bodies against both the real `secrecy` crate (pinned `0.8.0` / `0.10.1`) and the `secure-gate` compat shim side-by-side. Provides machine-verified proof of drop-in compatibility. Adds `~50` tests across `parity_v08.rs` (~24 tests), `parity_v10.rs` (~25 tests), and `divergence.rs` (5 tests). All test names include a `::real_secrecy` / `::compat_shim` suffix so failures pinpoint which side diverges. API coverage verified directly against local source clones of both secrecy versions.

### Documentation

- **`MIGRATING_FROM_SECRECY.md`** — new standalone guide covering both secrecy 0.8.x and 0.10.x: import swap tables, type mapping, step-by-step native migration, all `From` conversions, bridge impl examples, and security notes for the transition period.
- **README** — "Migrating from secrecy" section replaced with a short pointer to `MIGRATING_FROM_SECRECY.md`. Features table: added `secrecy-compat` row.
- **SECURITY** — Feature Security Implications table: added `secrecy-compat` row with security impact and recommendation. Compat layer security note added under Module-by-Module.

### Added

## [0.9.0-rc.2] - 2026-03-23

### Documentation

- **Rust API reference** — Rustdoc expanded so `#![warn(missing_docs)]` stays clean (errors, public traits, and main `Fixed` / `Dynamic` APIs).
- **README** — Encoding “Direct constructors” table uses one shared method column for `Fixed` and `Dynamic`.
- **SECURITY** — Version update.

## [0.9.0-rc.1] - 2026-03-22

### Breaking Changes

- **Rust edition 2021 → 2024** — requires Rust ≥ 1.85 to build. Users who cannot upgrade to Rust 1.85 should pin `secure-gate = "0.8"` and track the `release/0.8` LTS branch (edition 2021, MSRV 1.75, security patches backported).

- **`rust-version` raised 1.75 → 1.85** — drops support for toolchains older than Rust 1.85.0 (released February 2025). The 0.8.x line on `release/0.8` continues to support Rust 1.75 and older for users who cannot upgrade.

- **`rand` 0.9 → 0.10** (`src/fixed.rs`) — `rand_core::OsRng` has been replaced by `rand::rngs::SysRng`; the trait `TryRngCore` has been renamed to `TryRng`. If you depend on the `rand` feature and call `Fixed::from_random()`, no API change is visible — the migration is internal. If you use `rand` types directly alongside this crate, consult the [rand 0.10 update guide](https://rust-random.github.io/book/update-0.10.html).

### Changed

- **`bincode` dev-dependency 1 → 2** — the binary serde round-trip test (`tests/serde_suite/roundtrip.rs`) has been updated to the bincode 2 serde-compat API (`bincode::serde::encode_to_vec` / `bincode::serde::decode_from_slice`). This only affects running the test suite; there is no public API change.

- **Proptest coverage** — added comprehensive property-based round-trip tests for `encoding-bech32` and `encoding-bech32m` in `tests/proptest_suite/encoding.rs`. This brings bech32/bech32m to the same level of randomized testing as hex and base64url, exercising arbitrary payloads and HRP values.

### Dependencies

- `rand` (optional): 0.9 → **0.10** (MSRV 1.85)
- `subtle` (optional): 2.5 → **2.6**
- `zeroize`: 1.7 → **1.8** (aligns with fuzz workspace)
- `bincode` (dev): 1 → **2** (MSRV 1.85)
- `proptest` (dev): 1.0 → **1.10** (MSRV 1.84)
- `arbitrary` (fuzz): 1.3 → **1.4**

## [0.8.0-rc.1] - 2026-03-21

### Breaking Changes

- **Renamed `ExposeSecret` → `RevealSecret` and `ExposeSecretMut` → `RevealSecretMut` (#101)** — The two core access traits have been renamed. `RevealSecret` more accurately describes the capability ("this type supports controlled revelation of its secret contents") while keeping `expose_secret` / `expose_secret_mut` as method names preserves their warning tone for the escape-hatch paths. All method names (`with_secret`, `with_secret_mut`, `expose_secret`, `expose_secret_mut`) and all struct/macro/encoding API surfaces are **unchanged**. Only code that names the trait explicitly is affected: `use secure_gate::ExposeSecret` → `use secure_gate::RevealSecret`; `T: ExposeSecret` bounds → `T: RevealSecret`; same for the `Mut` variant. Users who only call methods via method resolution are unaffected.

- **HRP-primary Bech32/Bech32m APIs (#100)** — `FromBech32Str` / `FromBech32mStr`: primary decode is now `try_from_bech32(expected_hrp)` / `try_from_bech32m(expected_hrp)` (payload only); raw `(HRP, bytes)` is `try_from_bech32_unchecked` / `try_from_bech32m_unchecked`. `ToBech32` / `ToBech32m`: `try_to_bech32(hrp)` / `try_to_bech32m(hrp)` only (removed optional second HRP). `Fixed` / `Dynamic`: `try_from_bech32(s, hrp)` / `try_from_bech32m(s, hrp)` for validated decode; `try_from_bech32_unchecked` / `try_from_bech32m_unchecked` replace the old single-arg `try_from_bech32` / `try_from_bech32m`. Migrate: `"s".try_from_bech32()` → `try_from_bech32_unchecked()`; `try_from_bech32_with_hrp(hrp)` → `try_from_bech32(hrp)`; `try_to_bech32(hrp, None)` → `try_to_bech32(hrp)`; wrappers: `try_from_bech32_with_hrp(s, hrp)` → `try_from_bech32(s, hrp)`, `try_from_bech32(s)` → `try_from_bech32_unchecked(s)` (and Bech32m analogs).
- **Removed `ToHex::to_hex_left`** — the redacted-logging helper has been removed from the `ToHex` trait. The function allocated a full hex-encoded `String` of the entire secret and dropped it without zeroization on the truncation path, contradicting its intended "safe for logs" purpose. Callers should construct any redacted output according to their own threat model (e.g. `format!("{}…", &hex[..n])` wrapped in `zeroize::Zeroizing`).
- **Removed `ct-eq-hash` feature** — `ConstantTimeEqExt`, `ct_eq_hash`, `ct_eq_auto`, optional `blake3` and `once_cell` dependencies, `CT_EQ_AUTO.md`, and related benches/tests/fuzz targets are gone. Timing-safe equality is only [`ConstantTimeEq::ct_eq`](https://docs.rs/secure-gate/latest/secure_gate/trait.ConstantTimeEq.html) (`ct-eq`). Migrate: enable `ct-eq` and replace any `ct_eq_hash` / `ct_eq_auto` usage with `.ct_eq()`.
- **Renamed `_expect_hrp` Bech32 constructors to `_with_hrp`** — `Fixed::try_from_bech32_expect_hrp`, `Fixed::try_from_bech32m_expect_hrp`, `Dynamic::try_from_bech32_expect_hrp`, and `Dynamic::try_from_bech32m_expect_hrp` are now `try_from_bech32_with_hrp` / `try_from_bech32m_with_hrp`. The `_with_hrp` naming follows idiomatic Rust conventions (`with_capacity`, `with_header`, etc.) and avoids implying a panic on mismatch. Migrate: rename call sites; the method signatures and behavior are identical.

### Security

- **Serde visitor length error now redacted in release builds** (`src/fixed.rs`) — `serde::de::Error::invalid_length(vec.len(), ...)` embedded the actual received byte count unconditionally, inconsistent with every other length-revealing error in the codebase. In release builds the error is now `serde::de::Error::custom("decoded length mismatch")`; debug builds retain the detailed form for diagnostics.
- **Fixed critical panic-safety bug in `Dynamic<Vec<u8>>` and `Dynamic<String>` decode and deserialize paths** — `protect_decode_result` and the `core::mem::take`-from-`Zeroizing` pattern have been replaced with a `from_protected_bytes` helper (pre-alloc empty `Box` → `mem::swap` → infallible `Dynamic::from`). `Zeroizing::drop` now remains active across the only real allocation point, closing the OOM panic window that previously stripped protection. The same fix applies to both `Dynamic<Vec<u8>>::deserialize_with_limit` and `Dynamic<String>::deserialize_with_limit`. (#96)
- `Dynamic<String>` `Deserialize` now wraps the intermediate `String` in `Zeroizing` before construction, matching `Dynamic<Vec<u8>>` and `Fixed<T>`. (#97)
- `Dynamic<Vec<u8>>` and `Dynamic<String>` deserialization now reject inputs exceeding `MAX_DESERIALIZE_BYTES` (1 MiB by default). Oversized buffers are zeroized before rejection. `deserialize_with_limit` is available for custom ceilings. (#99)
- **`Fixed<T>` decoding stack residue documented** (`SECURITY.md`) — the `try_from_hex`, `try_from_base64url`, and related decoding constructors on `Fixed<[u8; N]>` use `copy_from_slice` into a stack-allocated `[0u8; N]` before moving the array into the wrapper. The intermediate stack slot is not explicitly zeroed before the move; in adversarial environments (core dumps, memory forensics) secret bytes may persist briefly on the stack. The compiler often eliminates the slot entirely in release mode. `Dynamic<T>` avoids this pattern via `from_protected_bytes` + `mem::swap` (heap-only path). Documented in `SECURITY.md` under Wrappers potential weaknesses.

### Added

- **`rust-version = "1.75"` in `Cargo.toml`** — documents the crate's MSRV. Rust 1.75 (October 2023) is the realistic floor for the current proc-macro dependency tree (`syn` 2.x, `unicode-ident`, `thiserror` 2.x all require ≥ 1.71–1.75) and provides approximately 2.5 years of toolchain coverage.
- **HRP-validating wrapper constructors** — `Fixed::try_from_bech32_with_hrp(s, hrp)`, `Fixed::try_from_bech32m_with_hrp(s, hrp)`, `Dynamic::try_from_bech32_with_hrp(s, hrp)`, and `Dynamic::try_from_bech32m_with_hrp(s, hrp)`. These enforce case-insensitive HRP matching at the wrapper level, returning `Bech32Error::UnexpectedHrp` on mismatch. The existing HRP-discarding constructors are retained but now carry a `# Warning` doc note directing security-critical callers to the `_with_hrp` variants.
- **`Dynamic<String>` allocator-level zeroization oracle** (`tests/heap_zeroize.rs`) — `check_string_zeroed` helper mirrors `check_vec_zeroed` and verifies via `ProxyAllocator` that the `String` backing buffer is fully zeroed before deallocation. Called at sizes 16 and 32 from the aggregate `all_heap_zeroed` test.
- **Generic macro test coverage** (`tests/macros_suite/fixed_generic.rs`, `tests/macros_suite/dynamic_generic.rs`) — exercises `fixed_generic_alias!` (basic instantiation at N=16/32, `size_of` check, and an explicit N=0 documentation test showing the absence of a compile-time guard) and `dynamic_generic_alias!` (Vec<u8> and String instantiation). `tests/macros_suite/mod.rs` updated accordingly.
- `std` feature: opt-in full `std` support that implies `alloc`. Use `features = ["std"]` if you need `std`-specific integrations; `alloc` (the default) remains sufficient for all current functionality.
- **Expanded zeroization integration test coverage** (closes #94):
  - `Fixed<[u8; N]>` tested for N = 8, 16, 32, 64, 128 via a parameterized macro; all cases use `core::hint::black_box` to prevent LLVM from eliding the zeroization write.
  - Pre-drop mutation tests for `Fixed<T>`: covers `with_secret_mut`, `expose_secret_mut`, custom `Zeroize` types, and scoped-access-then-drop patterns.
  - `Dynamic<[u8; N]>` heap zeroization verified at the allocator level for N = 16, 32, 64, 128 via `ProxyAllocator`.
  - `Dynamic<Vec<u8>>` backing-buffer zeroization verified for the same sizes with fill → `shrink_to_fit` → drop sequences.
  - Mutation sequence tests for `Dynamic<Vec<u8>>` and `Dynamic<String>` covering `push`, `truncate`, `extend_from_slice`, `shrink_to_fit`, and `with_secret_mut` before drop.
  - Spare-capacity zeroization tests for both `Dynamic<Vec<u8>>` and `Dynamic<String>`.
  - Scoped `with_secret_mut` + drop tests for `Dynamic<Vec<u8>>`.
  - `heap_zeroize.rs` refactored to a single aggregate `#[test]` (`all_heap_zeroed`) eliminating race conditions with the global `ProxyAllocator` state under parallel test execution.
  - All new tests run cleanly under `cargo test --no-default-features`, `cargo test --release --features alloc`, and `cargo +nightly miri test --features alloc`.
- Added ASan CI job (`asan-heap`) for heap zeroization verification using `cargo +nightly test --features alloc --test heap_zeroize -Z build-std`.

### Fixed

- **`rand` feature no longer forces `alloc`** (`Cargo.toml`) — `rand?/alloc` has been removed from the `rand` feature. `Fixed::from_random()` only fills a stack array via the OS RNG (`try_fill_bytes`) and requires no heap allocation; `rand` now works in pure `no_std`/`no_alloc` builds for `Fixed<T>`. `Dynamic::from_random()` continues to work when `alloc` is also active, since `Dynamic<T>` already requires `alloc` independently.
- **`tests/heap_zeroize.rs` hardened against silent false negatives and gate leakage** — test-only improvements, no library behavior changes: (1) `check_vec_zeroed` and `check_string_zeroed` now `assert_eq!(capacity, size)` after `shrink_to_fit` — without this, an allocator that rounds up capacity silently bypasses the proxy check producing a false negative; (2) `with_proxy_check` now uses a `CheckGuard` RAII struct to ensure `CHECKING` is cleared even when the closure panics — previously a panic left the gate open during stack unwinding; (3) all four helper closures now call `drop(secret)` explicitly to make drop timing clear and refactor-safe; (4) `Dynamic<String>` size coverage expanded from 2 to 4 sizes (16/32/64/128) to match `Dynamic<Vec<u8>>`; (5) Vec and String checks now interleaved in a `for size in [16, 32, 64, 128]` loop that structurally enforces size parity.
- **Wrong feature gate on `fixed_deserialize_wrong_length` test** (`tests/serde_suite/deserialize.rs`) — the test was gated `#[cfg(all(feature = "serde-deserialize", feature = "encoding-hex"))]`; hex encoding has no relationship to serde deserialization length checking. Corrected to `#[cfg(feature = "serde-deserialize")]` so the error path (including `Zeroizing<Vec<u8>>` drop on length mismatch) is exercised in minimal serde-only feature configurations.
- **`static` secrets + `panic = "abort"` footguns documented** (`SECURITY.md`) — `Fixed::new` is `const fn`, so `static SECRET: Fixed<...> = Fixed::new([...])` compiles silently but is never zeroized (Rust does not invoke `Drop` on program-scope statics). Additionally, `panic = "abort"` builds skip all `Drop` impls on panic, meaning secrets in scope at the time of a panic are not cleared. Both limitations are shared by the broader `zeroize` / `secrecy` ecosystem; they are now documented under _Wrappers — Potential weaknesses_ with concrete mitigation notes.
- **MSRV CI job** (`.github/workflows/ci.yml`) — runs `cargo +1.75 check` with default features and with `--features=full` on every push and PR. Previously, `full` was excluded from MSRV because `ct-eq-hash` pulled in `blake3` → `constant_time_eq` (edition2024). That feature has been removed.
- **Weak-dependency feature syntax throughout `Cargo.toml`** — every feature entry of the form `pkg/feature` where `pkg` is an optional dependency declared with `dep:` syntax has been changed to `pkg?/feature`. Without `?`, Cargo rejects the activation on MSRV toolchains because the optional dep has no implicit feature name. Affected entries: `rand?/alloc`, `hex?/alloc`, `base64?/alloc`, `bech32?/alloc`, `serde?/alloc`. The non-optional `zeroize/alloc` is unaffected.

### Changed

- **Encoding exposure model documented** (`README.md`, `SECURITY.md`, `src/traits/encoding/`) — `README.md` Encoding section rewritten to match the Equality section's upfront bullet style: three access patterns (direct method, `with_secret` closure, `expose_secret` escape hatch) with security trade-offs and audit-greppability callouts; full method reference table with fallible column and `_with_hrp` preference for Bech32; consolidated audit grep command; decode-side wrap-immediately note. Stale/incorrect "must call `expose_secret` first" claim removed from `base64_url.rs` module doc. "Audit visibility" security note added to `hex.rs`, `bech32.rs`, and `bech32m.rs`. `SECURITY.md` Encoding/Decoding mitigations block updated with exposure contract and audit grep caveat.
- **Proptest case counts raised to 256 with boundary strategies** (`tests/proptest_suite/`) — all `ProptestConfig::with_cases` overrides raised from 30/50 to 256. Variable-length vector arguments in `ct_eq_symmetric`, `dynamic_hex_roundtrip`, `dynamic_b64_roundtrip`, and `serializable_vec_roundtrip` now use `prop_oneof!` to guarantee empty, single-byte, and max-size inputs on every run rather than relying on random chance to hit them.
- **`serializable_secret_misuse` compile-fail test re-enabled** (`tests/compile_fail_tests.rs`, `tests/compile-fail/`) — the test was commented out due to a stale `.stderr` snapshot referencing `zeroize::DefaultIsZeroes` (removed in v0.8.0) and because `BadSecret` lacked a `Zeroize` impl, causing the compile error to land at `Dynamic::new()` rather than at `serde_json::to_string()`. Fixed by deriving `Zeroize` on `BadSecret` so construction succeeds and the error is correctly about `SerializableSecret` not being satisfied — the intended security boundary. Snapshot regenerated; test re-enabled with `#[cfg(not(miri))]` (same pattern as the sibling `fixed_alias_zero_size_compile_fail` test).
- **`fixed_generic_alias!` implementation notes rewritten** (`src/macros/fixed_generic_alias.rs`) — the previous note inaccurately referred to "a compile-time zero-size guard inherited from `Fixed<[u8; N]>`" that does not exist for generic aliases. The note now explains that `N=0` cannot be rejected at macro-invocation time (unlike `fixed_alias!`), that `SecretBuffer::<0>` compiles to a zero-byte type with no cryptographic utility, and directs callers to validate `N > 0` in their own tests.
- **`partial_eq_fallback` test renamed** (`tests/ct_eq_suite/basic.rs`) — renamed to `manual_comparison_without_ct_eq_feature` and given an explicit comment warning that the comparison is non-constant-time and that `ct-eq` + `ConstantTimeEq` should be used for security-sensitive equality.
- **`Bech32Error::ConversionFailed` documented as currently unreachable** (`src/error.rs`) — the variant is never produced: `.byte_iter()` on a successfully-validated `CheckedHrpstring` is infallible in the `bech32` crate; any bit-conversion failure surfaces as `OperationFailed` during the `CheckedHrpstring::new()` call. The variant is retained as public API for forward compatibility.
- **`Bech32Large` capacity documentation corrected** — all inline docs stated "~3.2 KB raw data"; the correct figure is ~5 KB (5,115 bytes maximum payload). Updated in `src/traits/encoding/bech32.rs`, `src/traits/encoding/bech32m.rs`, and `src/traits/decoding/bech32.rs`.
- **README serde section scoped** — the "no temporary string buffers" claim now explicitly excludes `Dynamic<String>`, which delegates deserialization to serde internals that may allocate non-zeroized intermediate buffers. `Fixed<[u8; N]>` and `Dynamic<Vec<u8>>` retain the guarantee. This scoping was subsequently resolved: `Dynamic<String>` deserialization now wraps its buffer in `Zeroizing` (#97), so the limitation no longer applies.
- **`cloneable_secret_works` extended** (`tests/core_tests.rs`) — wrapper-level `Fixed<CloneKey>` clone independence test added: creates a `Fixed<CloneKey>`, clones it, drops the original (triggering zeroization of its `Vec<u8>` backing), and drops the clone. Both sequential drops succeeding without panic proves the clone owns independent heap memory.
- **`try_from_bech32` / `try_from_bech32m` constructors now document HRP discard** — existing `Fixed` and `Dynamic` wrapper constructors carry a `# Warning` doc note directing security-critical callers to the HRP-validating variants (then named `_expect_hrp`, now renamed to `_with_hrp`).
- Version bump from 0.8.0-alpha.1 to 0.8.0-rc.1.
- **Breaking**: The `no-alloc` feature has been removed. To build without heap allocation (`Fixed<T>` only, embedded / pure `no_std`), use `default-features = false`. This matches the idiomatic Rust pattern used by `zeroize`, `serde`, `rand`, and others.
- The `compile_error!` guard that prevented `alloc` and `no-alloc` from being enabled simultaneously has been removed along with `no-alloc`.
- `heap_zeroize.rs` tests are skipped under Miri (`#![cfg(not(miri))]`) due to fundamental incompatibility between `#[global_allocator]` and Miri's Stacked Borrows model; heap zeroization is still verified in normal CI and under ASan.
- `compile_fail_tests.rs` trybuild test is skipped under Miri (`#[cfg(not(miri))]`) since compile-fail diagnostics are not relevant to runtime UB detection.

### Migration

```toml
# Before (0.8.0-alpha.1)
secure-gate = { version = "0.8", default-features = false, features = ["no-alloc"] }

# After
secure-gate = { version = "0.8", default-features = false }
```

```rust
// ct-eq-hash removal (if you used the old feature)
// Before
// secret_a.ct_eq_hash(&secret_b);  // or ct_eq_auto(...)
// After — enable `ct-eq` and use deterministic comparison:
secret_a.ct_eq(&secret_b);
```

## [0.8.0-alpha.1] - 2026-03-16

**Major breaking alpha release + critical security fix**

### Security

- **CRITICAL: Fixed zeroize-on-drop security flaw** (affects all versions 0.1.0–0.7.0-rc.15)  
  **Issue**: Despite documentation claiming "secrets are zeroized on drop", no `impl Drop` existed — only the empty `ZeroizeOnDrop` marker trait. Secrets were **never wiped** automatically on drop, creating a false sense of security.  
  **Impact**: All users relying on the documented guarantee had secrets persist in memory after drop, potentially exposing sensitive data to memory dumps, swap files, or other processes.  
  **Root cause**: Rust's E0367 rule prevents `Drop` impls with bounds stricter than struct bounds. The optional `zeroize` feature created conflicting bounds.  
  **Fix**: Made `zeroize` mandatory (no feature gate), added `T: Zeroize` bounds to struct definitions, and implemented real `Drop` handlers that call `zeroize()`. Zeroization is now guaranteed.  
  **Migration**: Users wrapping non-zeroizable types must implement `Zeroize` on them. Most crypto types already implement `Zeroize` out of the box.
- **All previous versions yanked**: 0.1.0 through 0.7.0-rc.15 were permanently yanked from crates.io on 2026-03-16 due to the above flaw.

### Breaking Changes

- `zeroize` is now a **required dependency** — no feature gate.
- `Fixed<T>` now requires `T: Zeroize`; `Dynamic<T>` requires `T: ?Sized + Zeroize`.
- Removed `zeroize`, `insecure`, `secure`, and `std` feature aliases entirely.
- `default` is now `["alloc"]` — users who had `features = ["secure"]` can drop it (already included by default).
- `no-alloc` builds remain possible for `Fixed<T>` (zeroize uses `default-features = false`).

### Added

- **Zeroize integration test suite** (`tests/zeroize_tests.rs` rewrite, issue #93)  
  Eight deterministic tests adapted from upstream RustCrypto/zeroize patterns
  (`zeroize/tests/zeroize.rs`, `zeroize/tests/zeroize_derive.rs`):
  - `fixed_direct_zeroize` — explicit `.zeroize()` zeroes `Fixed<[u8; 32]>` contents; verified via `expose_secret()`
  - `fixed_zeroize_on_drop` — `PanicOnNonZeroDrop` sentinel confirms `Fixed::drop` calls `zeroize()` before inner `Drop` runs; no `unsafe`, Miri-clean
  - `fixed_needs_drop` — `core::mem::needs_drop::<Fixed<[u8; 32]>>()` proves a real `Drop` glue destructor exists (would have returned `false` in all pre-0.8.0 versions — single-line regression proof for issue #92)
  - `dynamic_direct_zeroize_vec` / `dynamic_direct_zeroize_string` — `.zeroize()` empties the heap contents of `Dynamic<Vec<u8>>` and `Dynamic<String>`
  - `dynamic_spare_capacity_vec_zeroized` — `PanicOnNonZeroDrop` + `set_len` restore pattern verifies `Vec::zeroize()` byte-zeroes spare capacity (memory beyond `len` but within `cap`) via `with_secret_mut`
  - `dynamic_needs_drop` / `dynamic_needs_drop_string` — confirms real destructors exist for both heap variants
- **Heap-level zeroize verification** (`tests/heap_zeroize.rs`, issue #93)  
  Dedicated integration test binary with a `ProxyAllocator` (adapted from upstream
  `zeroize/tests/alloc.rs`) that intercepts OS deallocations and asserts all bytes of a
  `Dynamic<[u8; 64]>` backing allocation are zero before the memory is freed. Uses an
  `AtomicBool` guard to confine the assertion to the test's lifetime, preventing false
  positives from unrelated test-harness allocations of the same size.
- **Test suite reorganized** into domain-based directory suites (`ct_eq_suite/`,
  `encoding_suite/`, `serde_suite/`, `macros_suite/`, `proptest_suite/`) compiled into a
  single `integration` binary. Standalone binaries (`core_tests`, `error_tests`,
  `no_alloc_tests`, `zeroize_tests`, `heap_zeroize`, `compile_fail_tests`) are each
  auto-discovered by `cargo test --tests`. Replaced all old monolithic test files (`tests/codec/`,
  `tests/ct_eq_auto.rs`, `tests/ct_eq_tests.rs`, `tests/proptest_tests.rs`, `tests/serde/`,
  `tests/macros/`, `tests/insecure_tests.rs`).
- `**tests/common.rs`\*\*: shared helper module with `assert_redacted_debug` and
  `RevealSecret`/`RevealSecretMut` re-exports available to all suite sub-modules.
- **Bech32/Bech32m error-path test coverage** (`tests/encoding_suite/bech32.rs`): six new
  tests trigger actual `Bech32Error` variants through encode/decode calls — invalid HRP
  encoding, malformed string decoding, and decode-side HRP validation (happy path and
  mismatch) for both `bech32` and `bech32m`.
- **Fuzz targets**: new `fuzz/fuzz_targets/encoding.rs`, `serde.rs`, and `ct_eq.rs` covering
  encoding round-trips for all four formats, serde serialize/deserialize, and constant-time
  equality. Expanded `expose.rs`, `mut.rs`, `parsing.rs`, and `fuzz/src/arbitrary.rs`.

### Fixed

- Updated trybuild snapshots to resolve CI mismatches for all feature configurations.
- `**benches/ct_eq_auto.rs`\*\*: Wrapped all inputs outside `iter` in `std::hint::black_box()` to prevent constant-folding (matches fix already applied in `fixed_vs_raw.rs`). Corrected four inverted benchmark names where `_force_ct_eq`/`_force_hash` labels contradicted the actual threshold path taken (`ct_eq_auto` selects `ct_eq` when `len ≤ threshold`, `ct_eq_hash` when `len > threshold`). Collapsed duplicate `criterion_main!` pair into a single `#[cfg(feature = "ct-eq-hash")]` call.
- `**benches/ct_eq_hash_vs_standard.rs**`: Same `black_box()` fix on inputs. Added missing top-level imports (`ConstantTimeEq`, `ConstantTimeEqExt`, `Fixed`, `Dynamic`) — the bench previously failed to compile under `--features ct-eq-hash,alloc,rand`. Removed a redundant outer `#[cfg(feature = "ct-eq-hash")]` wrapping an already-specific inner `#[cfg(all(...))]`; collapsed duplicate `criterion_main!`.
- `**benches/serde.rs**`: Removed unused `extern crate alloc;` and corrected run command to `--features serde`. Added `#[derive(zeroize::Zeroize)]` to the local helper types (`SerializableArray32`, `SerializableVec`, `SerializableString`) — without it they could not be wrapped in `Fixed<T>`/`Dynamic<T>` (both require `T: Zeroize`), so the bench never exercised wrapper serialization at all. Added `Fixed<SerializableArray32>`, `Dynamic<SerializableVec>`, and `Dynamic<SerializableString>` serialize benchmarks alongside the existing newtype/raw comparisons, confirming zero-overhead delegation. Consolidated scattered local `use` statements into a single top-level import; fixed `.clone()` calls on non-`Clone` types. Moved 1 MB fixture allocation outside `iter()` so large benchmarks measure serialization rather than alloc + 2 × 1 MB `zeroize-on-drop` per sample.

### Changed

- Zeroization is no longer optional — always enabled and enforced.
- Documentation updated throughout to reflect mandatory zeroize requirement.
- `alloc` feature now enables `zeroize/alloc` for full spare-capacity wiping in `Dynamic<Vec<T>>`/`Dynamic<String>`.
- `**CT_EQ_AUTO.md**`: Refreshed all performance figures from a clean-machine run after the `black_box` fixes. Key corrections: 32 B ratio 1.7× → 2.3× (`ct_eq` ~~127 ns, `ct_eq_hash` ~288 ns); 100 KB figures reflect the permanent increase from `zeroize-on-drop` overhead (~~169 µs vs ~~565 µs, ~3.3×, not the pre-zeroize 6.5×); raw hash overhead corrected to ~59–75 ns; caching note now distinguishes 32 B cache miss (~~6%) from 1 KB alloc+zeroize cost (~70%); threshold crossover confirmed closer to 64 B; outlier ceiling ≤8% → ≤20%.

### Migration

- Update code to satisfy `T: Zeroize` (most real secrets already do).
- Replace any remaining optional-zeroize assumptions with mandatory behavior.

### CI / Dev

- CI matrix (`ci.yml`, `test_all.sh`) expanded: per-format encoding isolation configs added
  (`encoding-base64`, `encoding-bech32`, `encoding-bech32m`, `encoding-bech32 + bech32m`);
  `alloc` added to all `ct-eq`/`ct-eq-hash` entries so `Dynamic`-backed tests run; `rand`
  label corrected to reflect it always enables `alloc` via its feature graph.
- `fuzz-miri.yml`: `--skip` updated from stale `serde_core_without_marker_compile_fail` to
  `serializable_secret_misuse` (test renamed in refactor); the old name was a silent no-op
  that left the trybuild subprocess test unguarded under Miri.
- `tests/compile_fail_tests.rs`: `serializable_secret_misuse` now gated on
  `#[cfg(all(feature = "alloc", feature = "serde-serialize"))]`; previously triggered
  irrelevant missing-feature diagnostics under `--no-default-features`.

## [0.7.0-rc.1 through 0.7.0-rc.15] - YANKED (2026-03-16)

**All 0.7.0 release candidates were permanently yanked** from crates.io due to the critical zeroize-on-drop documentation flaw described in 0.8.0.  
These versions are no longer available and the repository was made private shortly after.

The following changes were developed during the 0.7.0-rc period (preserved for historical reference):

### Added

- **Polymorphic access traits**  
  `RevealSecret` and `RevealSecretMut` traits provide generic, zero-cost access with metadata (`len()`, `is_empty()`) without exposing contents. Implemented for both `Dynamic<T>` and `Fixed<T>`.
- **Timing-safe equality**  
  `ConstantTimeEq` trait (`ct-eq` feature) with `.ct_eq()` methods on `Fixed<[u8; N]>` and `Dynamic<T: AsRef<[u8]>>`.
- **Fast probabilistic equality for large secrets**  
  `ConstantTimeEqExt` trait (requires `ct-eq-hash` feature) extends `ConstantTimeEq` with methods for fast probabilistic equality using BLAKE3 hashing. Includes `ct_eq_hash()` for direct hash comparison and `ct_eq_auto()` for smart hybrid selection. Centralized threshold logic with default 32-byte crossover point.
- **Configurable decode priority in `try_decode_any`**  
  Added optional `priority: Option<&[Format]>` parameter for customizable decode order. Backward compatible with default (Bech32 → Hex → Base64url).
- **Enhanced decoding errors with hints**  
  `DecodingError` variants include hints (e.g., attempted formats) in debug builds only.
- `alloc` and `no-alloc` features for explicit heap control.
- `secure` includes `alloc` by default.
- `std` feature depends on `alloc`.
- **Per-format encoding/decoding traits** (orthogonal `ToHex`/`FromHexStr`, etc.)
- **Opt-in cloning & serialization** (`CloneableSecret`, `SerializableSecret` markers)
- **Secure random generation** (`from_random()` via the OS RNG)
- **Fallible fixed-size construction** (`TryFrom<&[u8]>` with `FromSliceError`)
- **Centralized errors** via `thiserror`
- Additional alias macros

### Changed

- **Error hardening with debug/release split** — detailed info in debug, generic in release.
- Testing & CI improvements (`trybuild`, serde fuzz, full feature matrix)
- Documentation overhaul (`SECURITY.md`, README, rustdoc)
- Serde support split into `serde-deserialize` and `serde-serialize` (gated by marker)

(Older versions below were also yanked but are preserved for history.)

## [0.6.1] - 2025-12-07 (yanked)

### Security

- Removed `into_inner()` from main wrappers (closes security bypass)
- Removed `finish_mut()` from heap types (bypassed exposure gate)

### Added

- Ergonomic RNG conversions (`FixedRng<N>` → `Fixed`)
- Convenience random generation methods

### Changed

- Macro visibility now requires explicit `pub` (no automatic fallback)

### Fixed

- Macro recursion in `dynamic_generic_alias!`

## [0.6.0] - 2025-12-06 (yanked)

### Breaking Changes

- Removed `Deref`/`DerefMut`, made inner fields private
- Removed inherent conversion methods (now trait-based)
- Replaced `RandomBytes<N>` with `FixedRng<N>`
- Removed `serde` feature (now gated by marker)
- Switched RNG to direct OS RNG access

### Added

- `len()`/`is_empty()` on fixed arrays
- Compile-time negative impl guard
- Direct OS RNG usage

### Fixed

- Lifetime issues in RNG
- `ct_eq` bounds

### Performance

- Direct OS RNG access improved keygen throughput 8–10%

## [0.5.10] - 2025-12-02 (yanked)

### Added

- `HexString` and `RandomHex` newtypes
- `PartialEq`/`Eq` for `Dynamic<T>`
- `RandomBytes<N>` newtype
- `random_alias!` macro
- Paranoia test suites

### Changed

- Renamed randomness methods to `.new()`
- Updated doc examples

### Fixed

- Privacy/import issues
- Doc-test failures
- Test assertions
- Macro expansion/orphan rules

## [0.5.9] - 2025-11-30 (yanked)

### Security & API Improvement

- All conversion methods now require explicit `.expose_secret()`

## [0.5.8] - 2025-11-29 (yanked)

### Added

- Optional `conversions` feature for `.to_hex()`, `.to_base64url()`, etc.

## [0.5.7] - 2025-11-27 (yanked)

### Added

- `rand` feature with `SecureRandomExt::random()`

### Documentation

- Complete rustdoc overhaul

## [0.5.6] - 2025-04-05 (yanked)

### Added

- Idiomatic `.into()` conversions for `Dynamic<T>`

## [0.5.5] - 2025-08-10 (yanked)

### Changed

- Renamed `view()`/`view_mut()` → `expose_secret()`/`expose_secret_mut()`

## [0.5.4] - 2025-11-23 (yanked)

### Added

- `AsRef<[u8]>` / `AsMut<[u8]>` for `Fixed<[u8; N]>`

## [0.5.3] - 2025-11-24 (yanked)

### Changed

- Documentation polish
- Fixed relative changelog link

## [0.5.2] - 2025-11-24 (yanked)

### Added

- Idiomatic `From` / `.into()` for `fixed_alias!` types

### Changed

- Removed inherent impls from macro (now generic)

## [0.5.1] - 2025-11-23 (yanked)

### Added

- `secure!`, `secure_zeroizing!`, `fixed_alias!`, `dynamic_alias!` macros
- `from_slice()` and `From<[u8; N]>` on aliases
- `finish_mut()` emphasis
- Macro test suite

### Changed

- `fixed_alias!` emits only alias; methods via generic impls

### Fixed

- README accuracy on zeroize
- Orphan rule violations
- Privacy/feature-gating

## [0.5.0] - 2025-11-22 (yanked)

### Breaking Changes

- Replaced `SecureGate<T>` with `Fixed<T>` and `Dynamic<T>`
- Removed `ZeroizeMode`, manual wiping, password specializations, `unsafe-wipe`

### Added

- Zero-cost fixed-size secrets
- `Deref`/`DerefMut` ergonomics
- Macros for constructors/aliases
- `into_inner()`, `finish_mut()`
- `Clone` for `Dynamic<T>`

### Fixed

- No unsafe when zeroize off
- Full spare-capacity wipe
- Consistent API

### Improved

- Modular structure
- Unit tests

## [0.4.3] - 2025-11-20 (yanked)

### Fixed

- Documentation mismatch

## [0.4.1] - 2025-11-20 (yanked)

### Added

- Configurable `ZeroizeMode` enum
- New constructors with modes

### Changed

- Unified zeroization through `Wipable` trait

### Fixed

- Full wiping for empty allocated vectors
- Clone preserves mode

## [0.4.0] - 2025-11-20 (yanked)

### Breaking Changes

- Unified under `SecureGate<T>`

### Added

- `SG<T>` alias
- `Zeroizing` for fixed-size

### Deprecated

- Old names

## [0.3.4] - 2025-11-18 (yanked)

### Documentation

- Updated README

## [0.3.3] - 2025-11-18 (yanked)

### Added

- Direct exposure methods on password types

## [0.3.1] - 2025-11-17 (yanked)

### Changed

- Renamed `SecurePasswordMut` → `SecurePasswordBuilder`

## [0.3.0] - 2025-11-13 (yanked)

- Initial public release

## [0.1.0 - 0.2.3] - 2025-11-15 / 2025-11-16 (yanked)

Crates.io releases from closed development before this changelog existed (`0.1.0` through `0.2.3`). No per-version notes were kept. All yanked (see bulk yank notice for `0.1.0`–`0.7.0-rc.15` elsewhere in this file). **0.1.0** published 2025-11-15; **0.2.3** (last in span) published 2025-11-16.
