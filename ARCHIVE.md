# Parked: audit tooling and the corpora that measured it

**This branch is not for merging into `main`.** It exists so two artifacts are
not deleted for want of context. Nothing here is a dependency of the crate:
`tools/cargo-secure-gate/` declares its own workspace, and `sweep-handover/` is
in `workspace.exclude`, so neither can reach the library's two-line `cargo tree`.

| Path | What it is |
| --- | --- |
| `tools/cargo-secure-gate/` | A source-level audit pass for code holding secrets in this crate. Two rules: a `FixedStorage` impl contradicted by its own fields, and a `Dynamic::new_with` closure that fills a buffer it never sized. |
| `sweep-handover/` | Allocator-verified corpora and the instruments that produced them, written independently of the tool. |

## What it is worth

Measured by someone who did not write it, against corpora they did write:

- **SG001 (the `FixedStorage` assertion): 4 of 4, zero false positives.** It
  defeated a non-ASCII type name, a growable field behind a `type` alias, a
  generic instantiation, and a two-level field path.
- **SG002 (`new_with` growth): 1 of 1 in its scope.**
- Zero findings on both clean controls, one of which a predecessor regex scanner
  reported ten false findings on, including one at its highest severity.
- It found a real defect in this repository: `impl FixedStorage for CloneKey {}`
  over a `Vec`-wrapping type, written by the migration that introduced the bound
  and missed in review. Removed upstream in `74c1838`.

## Why it is parked rather than shipped

The tool mirrors invariants that live in `src/`, as constant lists. In roughly
two days of crate work, three separate commits invalidated it:

| Commit | Effect |
| --- | --- |
| `fe64ef8` | Flipped the `FixedStorage` predicate from resizability to heap ownership. The tool silently blessed `Box<[u8]>`, which the crate rejects — a false negative in its best rule. |
| `9eabeec` | Grew the allow-list from five `NonZero` types to twelve. |
| `dfcdd04` | Rejected `dynamic_newtype!(.., generic Vec<u8>)`, retiring a planned rule. |

None was caught by the tool's own 30 tests. The failure mode is a silent wrong
answer in a security tool, which is worse than no tool — this crate's main asset
is that `SECURITY.md` does not overclaim, and a scanner that emits green while
stale works against that.

The second reason is arithmetic. The cost falls on the maintainer, now; the
benefit falls on consumers with more `FixedStorage` impls than a person can read.
This crate has about ten. At ten it is a review problem, not a tooling problem.

## When to revive it

When consumers exist with enough marker impls that eyeballing them does not
scale. The tool is complete enough to run, and the corpora give it a ground truth
that does not depend on its author's blind spots.

## The part worth keeping regardless

Not the code — the rule. **`FixedStorage`, `CloneableSecret` and
`SerializableSecret` are assertions the compiler does not check**, so the audit
action is to grep the impls and read the fields. That sentence found `CloneKey`.
It belongs in `SECURITY.md`, where it cannot go stale.

## Running what is here

```sh
# The tool: 30 tests, builds on the repository's pinned toolchain.
cargo test  --manifest-path tools/cargo-secure-gate/Cargo.toml
cargo run   --manifest-path tools/cargo-secure-gate/Cargo.toml \
    --bin cargo-secure-gate -- src tests benches fuzz

# Recall and precision against a corpus whose answers are known.
cargo run --manifest-path tools/cargo-secure-gate/Cargo.toml --bin score -- \
    --leaking sweep-handover/corpora/adversary/src/evade.rs \
    --clean   sweep-handover/corpora/adversary/src/good.rs

# The instruments. --test-threads=1 is NOT optional: they keep watch state in
# process-global atomics, and about 43% of parallel runs misattribute, in both
# directions. Documented in sweep-handover/README.md by their author.
cargo test --manifest-path sweep-handover/corpora/adversary/Cargo.toml -- --test-threads=1
```

Two caveats on every number those instruments report, both from their author:
each growth-driven byte count is the **forced-move worst case**, since neither
instrument overrides `realloc`, so every capacity change is made to move; on a
quiet heap the allocator may extend in place and abandon nothing. And allocation
counts are floors, since neither overrides `alloc_zeroed`.

Every command above was run on this branch before it was written down: 30 tool
tests pass, the crate scans clean on both rules, and both instrument tests
(`evasions_leak_for_real`, `correct_code_leaks_nothing`) pass — so the ground
truth the tool was measured against is reproducible here, not only asserted.

Branched from `main` at `e504fd1`.
