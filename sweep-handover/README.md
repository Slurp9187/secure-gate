# Measurement instruments and corpora for auditing `secure-gate` consumers

**Not part of the crate.** Nothing here is built, tested, or depended on by `secure-gate`;
`Cargo.toml`'s `include` list keeps it out of any published crate, and `workspace.exclude` keeps
the corpora crates out of the crate's own build. This branch is not intended to be merged.

**What this is for.** Auditing a *consumer* of `secure-gate` has one hard problem: deciding
whether a piece of code actually abandons an unwiped heap buffer holding a secret. No static
tool can answer that — so these are the instruments that can, plus the corpora that were
measured with them. They exist so that work on `tools/cargo-secure-gate` has ground truth
instead of prose.

```
corpora/adversary/    11 measured leak cases + a provably-clean file + an allocator instrument
corpora/evasion/      9 numbered evasion cases + benign.rs + an allocator instrument
corpora/helpers/      a support crate the evasion corpus depends on
corpora/robustness/   hostile inputs for a scanner, plus a generator for the oversized ones
```

## Read this before trusting any number here

Three properties of the instruments are defects, or near enough, and every figure below depends
on them.

1. **The instruments are flaky under parallel test execution.** Both keep their watch state in
   process-global atomics while `cargo` runs the test binary's tests concurrently. Measured:
   roughly **43% of default-mode runs fail**, and the mis-attribution goes in *both* directions
   — a clean negative control was once reported as leaking. **Always run with
   `--test-threads=1`.** Fixing this properly means serialising the watch (a mutex) or giving
   each test its own process.

   ```sh
   cargo test --manifest-path corpora/adversary/Cargo.toml -- --test-threads=1
   cargo test --manifest-path corpora/evasion/Cargo.toml  -- --test-threads=1
   ```

2. **Every growth-driven byte count is the forced-move worst case.** Neither instrument
   overrides `realloc`, so the `GlobalAlloc` default path — allocate, copy, deallocate — is
   taken and *every* capacity change moves the block, guaranteeing the old buffer passes through
   `dealloc` with its bytes still readable. On a quiet heap, libc's `realloc` may extend in
   place and abandon nothing. So "leaks: yes" means **"leaks whenever the growth moves"**, and
   the byte figure is an upper bound for one growth.

   Five sites are exempt and are the strongest evidence in the set, because no reallocation
   decision is involved at all: `split_off` (504 of 504 bytes), the `append` donor (512 of 512),
   and three whole-buffer replacements (1584, 1520, 1488) where capacity is *identical* before
   and after — which also means any capacity-watching heuristic is blind to that class by
   construction.

3. **Allocation counts are floors.** Neither instrument overrides `alloc_zeroed`, so read
   "0 allocations" as "none through `alloc`". Byte counts are unaffected: they come from
   `dealloc`.

Two further figures are census floors rather than totals (1984 bytes across 5 blocks, and 960
across 4): that mode filters to blocks holding ≥ 64 consecutive payload bytes, so the small
doubling steps are excluded.

## The structural result that shapes any tool built on this

**A static scan cannot detect the growth transaction, only the route to it.** Reallocation is a
runtime property. One `v.push(b)` has four outcomes depending on capacity at that instant:

| | condition | residue |
|---|---|---|
| 1 | `len < cap` | nothing allocated, none |
| 2 | `len == cap`, allocator extends in place | none |
| 3 | `len == cap`, allocator moves the block | the old buffer, secret intact |
| 4 | `cap == 0` | fresh allocation, no old buffer, none |

Case 2 is measured: growing from capacity 1008 by 96 bytes extends in place and leaks nothing.
So a source-level rule reports a **route**, not an event — and a report that says otherwise is
selling certainty it does not have. The design that follows is an *assertion auditor that
inventories growth routes*, never a leak detector, with two output sections rather than one
severity list: unchecked assertions to review by hand (high precision, actionable), and growth
routes reachable from an exposed mutable reference (an inventory).

## What was measured against these corpora

Two tools have been pointed at them.

**`tools/cargo-secure-gate`** (Rust, `syn`-based, on its own branch) — on the one rule it had
shipped: **4 of 4** allocator-verified false-`FixedStorage`-assertion sites caught, **zero**
false positives on measured-clean code. It defeated a non-ASCII identifier, a type alias hiding
the growable field, a generic instantiation, and a two-level field path which it reported as the
full transitive path. Its misses are almost entirely in a rule its README lists as not yet
written; of 37 measured sites, exactly one falls inside a shipped rule and is missed, via a
consumer trait method outside the op allowlist.

Caveat on that result, recorded here because it is easy to over-read: **those numbers hold for
these corpora scanned in isolation.** A same-name type collision across files defeats the rule
in both directions — one unrelated file reusing the type names erases the catches to a green
exit, and the mirror direction manufactures a finding — with the outcome depending on scan
order.

**A Python regex scanner** (deliberately not included here) — 0 of 11 on the evasion corpus and
**10 false findings** on the clean file, one of them CRITICAL, triggered by a *doc comment*
explaining why a type was safe. Pointed at one leaky file and one clean one, every finding
landed on the clean file: output inverted with respect to the truth. It is not in this directory
because a measurably inverted scanner, published under this crate's name, would mislead people
no matter what its README said.

The lesson worth carrying, from both: the corpus an author writes shares its blind spots with
the tool that author wrote. Only an independently written corpus produces a real recall number.

## Defect classes these corpora were built to expose

Each is a design trap rather than a bug in one implementation's regexes or visitors:

- Reading raw, unmasked source for a struct body — a doc comment mentioning `Vec` becomes a
  CRITICAL finding, quoting the developer's own safety comment as the evidence.
- Matching a suppression directive against raw source, so prose or a string literal *mentioning*
  the directive disables the scan. Documenting the tool switches the tool off.
- Computing the exit code after display filters, so a noise knob silently becomes a detection
  knob.
- Accepting an unknown rule id and exiting 0 — a one-character CI typo becomes permanent green.
- Copying a matched literal into the output, so the rule that means "you hardcoded a credential"
  reproduces it into CI logs.
- Counting growth statements globally instead of per access path, so two *different* fields each
  getting one bulk fill reads as repeated growth.
- Name heuristics matching substrings: `mac` inside `MachineIdBlock`, `auth` inside
  `AuthorTagBlock`.
- Rules that are unsatisfiable by construction, so a consumer carries findings that can only be
  suppressed — the shape that gets a linter switched off entirely, taking the good rules with it.
- Silence where a subject cannot be resolved. An unresolvable assertion must be reported as
  "could not check"; silence is the one output a security auditor must never produce.
- Flat, unqualified type-name maps (see the collision note above).
- A closed method vocabulary, which an author walks past by naming their own method.

## Provenance and caveats on the corpora themselves

Produced in automated sessions working on this repository, while adding the `FixedStorage` bound
to `Fixed::new`. The adversary corpus and the evasion corpus are kept separate because they were
written independently and disagree; the disagreement is the point.

One artefact of that history is worth recording rather than quietly deleting. The evasion
corpus shipped an `examples/probe.rs` containing `fixed_newtype!(pub Bad, generic Vec<u8>)` and
`Fixed::new(vec![0u8; 4])` — both of which are now **hard compile errors**, because the
`FixedStorage` bound closed exactly that hole. The corpus written to find the weakness contained
the weakness. The file is removed here because it would not build; what it demonstrated is this
paragraph.

Both were built to attack the Python scanner, so the case mix over-weights post-construction
mutation and under-weights construction-time growth. They are **not** a benchmark designed for
any current tool, and a raw caught/total ratio against them is not a fair summary of one.
