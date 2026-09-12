# cargo-secure-gate

A source-level audit pass for code that holds secrets in `secure-gate`.
**Prototype** — two checks, built to find out whether the noise floor is
tolerable on real code. It is not published and is not a dependency of the
library; see [Placement](#placement).

```
cargo secure-gate [--format human|json] [--deny-routes] <path>...
```

Exit code is 1 when a contradicted assertion is reported. Growth routes are an
inventory rather than findings, so they do not fail a run unless `--deny-routes`
says to.

## Why a source pass exists after #201

#201 moved a good deal into the type system: `Fixed::new` now requires
`FixedStorage`, so `Fixed<Vec<u8>>`, `Fixed<String>` and `Fixed<[Vec<u8>; 2]>`
stopped compiling. What is left is not oversight. It is the residue of two
decisions, each deliberate, each documented where it was made, and each leaving
a gap a reader can check by eye on one type but not across a codebase.

### SG001 — a `FixedStorage` assertion contradicted by the type's own fields

`src/traits/fixed_storage.rs` states the limit itself:

> Like `CloneableSecret`, the compiler checks that you wrote the impl, not that
> the claim is true. A type with a `Vec` field that implements `FixedStorage`
> anyway will compile and will leak, which is measured and deliberate: the
> alternative is a closed set of blessed types, and that would break the one
> thing the `generic` arm of `fixed_newtype!` exists for.

That is the right trade — a closed set would be worse. SG001 reads the fields
and says whether they agree with the impl, resolving local types transitively,
through arrays, tuples, `Option`, `Box` and enum variants.

Running it over this repository at `519e87b` finds one: `CloneKey(Vec<u8>)` in
`tests/core_tests.rs:278`, which asserts `FixedStorage` and owns a `Vec`. It is
test-only code and nothing ships from it, but it is exactly the documented shape,
and it entered in `ed099f9` — the commit that introduced the bound — as one of
ten impls added so the suite kept compiling. Nine of the ten are sound.

### SG002 — a `Dynamic::new_with` closure that fills a buffer it never sized

`SECURITY.md`, on the constructor it otherwise recommends:

> `new_with` starts the closure with an empty `Vec`, so a closure that fills it
> byte by byte reallocates its way up and abandons its own intermediate buffers:
> measured at 1016 secret bytes across 7 abandoned blocks for a 1008-byte secret.
> Call `v.reserve_exact(len)` first, or build the value and use `Dynamic::new`,
> both of which measured 0.

Seven abandoned buffers, before the wrapper has finished being built, from the
constructor the documentation points at. The fix is one line.

## Three ways to get these checks wrong

All three were live possibilities; the third was a real bug in the first draft,
found by running the tool over this repository.

**Keying SG002 on growth.** `SECURITY.md` is explicit that the property is
*capacity-changing*, not growing — `shrink_to_fit` abandons a buffer while the
buffer only ever got smaller, and "a check keyed on 'bytes added' would miss it".
That framing governs a mutation-site check. Inside `new_with` the buffer starts
empty, so growth is the only way its capacity changes and a shrink abandons
nothing: the narrower vocabulary here follows from the scope, and does not
generalise to the mutation sites.

**Treating `reserve` as a hazard everywhere.** On a buffer that already holds a
secret it is one — it abandons the buffer while writing no payload at all, which
is the case a "bytes added" check misses. On the empty buffer `new_with` hands
over, the same call is the recommended fix. One shared list of capacity-changing
calls would flag the mitigation as the weakness.

**Treating one bulk fill as the measured shape.** `v.extend_from_slice(m)` into
an empty buffer allocates once and abandons nothing, because there is no earlier
buffer to abandon. The first draft flagged it, which put three findings on this
repository's own tests that were not there. What was measured is a closure that
fills *byte by byte*. So: growth inside a loop, or two growth calls in sequence,
is an error; a lone iterator-driven `extend`, whose reallocation count lives in a
size hint this pass cannot read, is a warning; a lone bulk fill is clean.

## Two kinds of claim, two sections

A `FixedStorage` impl contradicted by its own fields is decidable from the
source: the impl is wrong whether or not a secret ever flows through it. A
growth route is not. Whether a `push` past capacity reallocates depends on the
allocator and the heap at that instant, and `SECURITY.md` measures the benign
case — a full 1008-byte buffer grown by 96 extends in place and abandons nothing.
One `push` line has four possible outcomes and only one of them leaves residue.

So the report has two sections and says which is which. Reporting both in one
severity list invites the reader to take a route for an observed leak, and the
summary line says "no other known shape was found in the scanned text" rather
than anything that rounds to "clean".

## What it does not claim

Nothing here observes memory. The measurements it quotes come from
`tests/lifecycle_trace_heap.rs`, which installs a global allocator and counts
non-zero bytes in freed blocks — that is the instrument that can say whether a
buffer was abandoned. This pass reads source and recognises shapes that were
measured there.

So a clean run is not a proof. Sites the pass cannot resolve — a buffer handed to
a helper function, a receiver declared in a crate that was not scanned, a field
whose type is foreign — are reported as `unresolved` rather than skipped, because
a silent skip reads exactly like a pass. `tests/corpus.rs` pins that distinction
in both directions.

## Recall is unmeasured

Precision is pinned by the fixtures below and by running over this repository:
one finding, nothing unresolved, no false positives. **Recall is not.** A peer
sweep of this crate measured a regex prototype at 6 of 26 against a deliberately
evasive, allocator-verified corpus, with the misses systematic rather than
random — anything that rebinds the exposed reference before growing it.

Three of those shapes were run against this pass directly. Two it already
handled and one it did not:

| Evasion | Result |
| --- | --- |
| Trigger phrases in comments and string literals; unrelated `Vec::push` nearby | not flagged, correctly — parsing makes this free |
| `impl FixedStorage for Ключ` | flagged — Rust identifiers are XID, and `syn` reads them |
| `let alias = v;` then `alias.push(..)` | **missed, silently** — now fixed, with aliases tracked through `let` and reborrows |

That third one is the reason the unresolved category exists, and it still got
through: a miss that leaves no trace is worse than a miss that says so. The
dataflow cases beyond a single rebinding — the buffer passed to a helper, or
reached through a trait object — are reported as unresolved rather than followed.

Getting the real number needs that evasion corpus. Until then, treat the
precision result as measured and the recall as unknown.

## Tests

Fixtures are the scenarios from `tests/lifecycle_trace_heap.rs`, and the expected
verdicts are that suite's measured results rather than this author's intuitions
about Rust:

| Fixture | Corpus scenario | Measured | Expected |
| --- | --- | --- | --- |
| `presized_new_with.rs` | `check_new_with_keeps_the_closures_buffer` | 0 bytes | clean |
| `capacity_stable_mutation.rs` | `check_capacity_stable_mutation_stays_in_one_buffer` | 0 allocations | clean |
| `single_bulk_fill.rs` | `dynamic_vec_new_with_fills_correctly` | one allocation | clean |
| `unsized_new_with.rs` | `SECURITY.md` | 1016 bytes / 7 blocks | error |
| `fixed_storage_honest.rs` | `FixedStorage` module docs | — | clean |
| `fixed_storage_contradicted.rs` | the documented hole | — | error |

The negative cases carry as much weight as the positive ones. A tool that flags
`Fixed::new_with`, or the capacity-stable mutation `SECURITY.md` recommends,
teaches its users to ignore it.

## Placement

Its own workspace root, for the reason `fuzz/` is one: `secure-gate` advertises a
two-line `cargo tree` and nothing here may ever appear in it. The library's
`include` list does not name `tools/`, so this directory is absent from the
published package. It builds on the repository's pinned 1.85 toolchain, so
running it needs no toolchain switch.

## Not yet written

- **SG003, capacity-changing mutation** through `with_secret_mut`,
  `expose_secret_mut` and `as_wrapper_mut` — the check that needs the full
  capacity-changing vocabulary, `shrink_to_fit` included. Its corpus entries
  already exist: `check_growth_orphan_retains_secret_vec`,
  `check_growth_orphan_via_expose_secret_mut`, `check_truncating_mutation_wipes_the_abandoned_tail`.
- **SG004, a zero-sized `Fixed`** — cheap, and the case for it is that
  `SECURITY.md` documents the compile-time guard as one `cargo check` does not
  report and an `#[inline]` library boundary defers to consumers. A parse-time
  match has neither limit.
- **`dynamic_newtype!(pub Name, generic Vec<u8>)`**, which `SECURITY.md` names as
  outside the `FixedStorage` bound and without `Dynamic<Vec<u8>>`'s `io::Write`
  escape.
- Type resolution via dylint, for the cases alias and newtype tracking cannot
  reach. Everything above is decidable without it. A peer built and ran one:
  receiver-aware and type-aware as hoped, 2 genuine warnings with none of
  clippy's false positives — but 1 of 5 growth paths caught, the four misses all
  indirect, which is a dataflow problem rather than a lint-authoring one. It
  costs a nightly toolchain, `rustc-dev`, `clippy_utils` pinned to a git rev, and
  a packaging bug in dylint 6.0.4. Precision is not the binding constraint here;
  recall is, and dylint does not fix recall.
- A manifest check. `full` does **not** include `std` (`Cargo.toml:110`), and
  `io::Write` for `Dynamic<Vec<u8>>` is gated on `std` (`src/dynamic.rs:776`) —
  so a consumer building with `full` has no safe growth path at all, and every
  growth route is a raw `Vec` reallocation. That is a Cargo.toml question this
  source pass cannot see, and it changes how a route should be read.
- `clippy.toml` is not a delivery mechanism: a config shipped inside a library is
  ignored, only the linted crate's own root is read, and `disallowed_methods` is
  path-based with no notion of a receiver — it cannot say "`push` on a `Vec` that
  came out of `expose_secret_mut`", so it fires on every `Vec::push` or none.
