# Heap-reallocation residue: what the harness measures

Status: accepted
Section it serves: [`SECURITY.md`](../../SECURITY.md) §2, *Heap-reallocation residue*
Artifacts: `residue-probe/` (the reusable probe crate), `tests/residue_support/mod.rs`, `tests/heap_residue.rs`,
`tests/heap_residue_nowipe.rs`, `tests/heap_residue_wiped.rs`,
`examples/zeroizing_alloc_app.rs`, `tools/pgo_allocator_compare.sh`,
`docs/design/receipts/`

`SECURITY.md` §2 documents a hazard this crate cannot fix from inside a library. A capacity
change through `with_secret_mut` / `expose_secret_mut` reallocates entirely outside
`secure-gate`, and the abandoned block is freed with the secret still in it. The remedy the
section points at — a zero-on-deallocate global allocator — can only be applied by the final
binary, because `#[global_allocator]` may appear once per program.

This document records what the artifacts listed above actually measure, so a reader can tell
the measured claims apart from the ones nobody here has measured.

**Nothing in this set tests `secure-gate`.** The crate is `#![forbid(unsafe_code)]` and can
never install an allocator. The subject is the hazard §2 documents and an allocator installed
the way an application installs one; the audience is the application author who can make that
choice.

## The three configurations

Each file under `tests/` compiles to its own binary, which is what lets three
`#[global_allocator]` declarations coexist in one crate. Each binary is one
`residue_binary!` invocation, and the three differ from one another in exactly one argument
— the role, which is the allocator the macro installs and the assertion its single test
makes. The probe mechanism itself — the spy, the non-wiping wrapper, the pattern counting,
and that macro — lives in the `secure-gate-residue-probe` crate so a downstream application
can run the same three configurations against its own workload;
`tests/residue_support/mod.rs` holds only this crate's §2 workload shapes.

| Binary | Allocator | What it proves |
|---|---|---|
| `tests/heap_residue.rs` | bare `Spy` | the residue **is** released: there is something to wipe |
| `tests/heap_residue_nowipe.rs` | `NoWipe<Spy>` | the probe sees it **in the composed position** |
| `tests/heap_residue_wiped.rs` | `ZeroAlloc<Spy>` | none of it survives |

### Why two configurations are not enough

A subject reporting zero hits is not yet a measurement. `blocks > 0` shows the counter ran; it
does not show that the spy reads the bytes it claims to read, at the position it claims to read
them. A spy observing the wrong memory reports clean under the subject, and nothing in a
two-configuration harness contradicts it.

The third leg closes that. `NoWipe<Spy>` has a zeroizing allocator's composition and its
`realloc` route and does not wipe, so it differs from the subject by exactly one thing. A probe
that is looking in the wrong place reports clean *here too* — and here a clean result is a
failure. That is what turns the subject's zero from a silence into a measurement.

The subject asserts **both** `pattern_hits == 0` **and** `blocks > 0`. Zero hits with zero
blocks inspected is a blind probe, not a wipe.

### What is counted

A planted pattern, not non-zero bytes. `PATTERN` is eight distinct non-zero bytes tiled across
the secret, and the spy counts occurrences of exactly that. Counting every non-zero byte would
measure the workload as much as the hazard — allocator bookkeeping, `Vec` headers and harness
scratch all read as non-zero — so the figure would be an upper bound needing explanation
afterwards. A pattern this harness planted cannot be inflated by incidental data, and it
survives a change of workload: a configuration's `0` then means *none of the secret came back*,
rather than *not much came back*.

### Where the probe reads, and why offset 0 is a consequence rather than a constant

Composed as `ZeroAlloc<Spy>`, the order is
`ZeroAlloc::dealloc` → wipe → `Spy::dealloc` → **read** → `System::dealloc`. The system
allocator has not been told about the block yet, so no free-list links have been written into
its head and the whole block is honest to read.

A probe that inspects a block *after* free does not have that: it must skip a prefix — two
words in a small glibc bin, four once the block is sorted into a large one — and a skipped
prefix is exactly where short residue hides. If the spy is ever moved within the composition,
re-derive the offset rather than inheriting `0` as a constant.

## The realloc rule: a control must release memory by the same route as the subject

This is the rule most likely to be "tidied" back into a false pass, so it is stated here as
well as in the source.

`Spy::realloc` is deliberately **not** `System.realloc`. It is move-always: allocate the
replacement, copy, release the old block through its own `dealloc`. `NoWipe` leaves `realloc`
to the `GlobalAlloc` default, which has the same shape.

If any configuration forwarded `realloc` to the system allocator, libc would release the old
block inside C. It would never reach `dealloc`, the probe would never see it, and the harness
would report a clean pass **on precisely the blocks nobody inspected** — which are the entire
defect class §2 is about. A zero-on-deallocate allocator that does not implement `realloc`
takes the `GlobalAlloc` default for the same reason, so mirroring it in the controls keeps the
wipe as the only difference between the three binaries. `secure-gate`'s existing
`ProxyAllocator` in `tests/heap_zeroize.rs` already declines to override `realloc`, so the repo
is consistent on this point.

A second consequence, which two assertions rest on: the old block is released *after* its
replacement has been allocated, so the replacement cannot be handed back the old block's
address. That is what makes "did the buffer move?" decisive rather than vulnerable to address
reuse.

## The workloads are §2's own shapes

So that the numbers in the documentation and the numbers in the tests are the same numbers,
both workloads are shapes `SECURITY.md` §2 already describes:

- **Growth-move** — a 4 KiB secret grown one byte past its capacity through `with_secret_mut`,
  with an allocated neighbour behind it so the reallocation has to move rather than extend in
  place.
- **Truncate-then-shrink** — a pre-sized 4096-byte buffer truncated to 2048 and then shrunk,
  abandoning a block that holds the live prefix *and* the discarded tail. §2's own point is
  that the property is *capacity-changing*, not growing, so a harness that only grew would
  under-test the section.

Each workload **asserts the abandonment happened**, by capturing the buffer's address before
and after the capacity change and requiring that it moved. `Vec::shrink_to_fit` is documented
as *may* reduce capacity; whether it reallocates is an allocator and standard-library
implementation detail. If it ever declined, no block would be abandoned, the planted pattern
would never be released, and every configuration would report a clean count for a run in which
nothing happened — the same false pass the `NoWipe` leg exists to prevent, arriving through the
workload instead of through the probe.

## One aggregate test per binary, and a foreign-thread counter

The counters are process-wide statics, so the measurement is sound only while one thread is
allocating inside the armed window. The usual answer is `--test-threads=1`, and this repo's CI
does not pass it: neither the `test` job nor `test-release` gives `cargo test` that flag, and
`.cargo/config.toml` does not set it. So the requirement is structural — one `#[test]` per
binary, the same convention and the same reason as `all_heap_zeroed` in
`tests/heap_zeroize.rs`. `residue_binary!` generates exactly one, which is how the convention
is kept rather than remembered.

That alone is not sufficient, and it should not be recorded as if it were. libtest's default
harness runs even a single test body on a *spawned* thread with the main thread parked, so the
armed window always has another live thread in it. That thread is blocked and the risk is low,
which is worse than high: it passes for months and then produces one inexplicable count. Each
binary therefore records the thread that armed the gate and asserts that **zero** deallocations
arrived from any other thread, which converts a silent skew into a named failure.

## Scope limits

Stated so they are not quietly widened later.

**Heap only.** These binaries observe blocks at the moment a global allocator releases them.
They say nothing about residue left by a *stack* move, nothing about pages written to swap, and
nothing about what a core dump contains. §2 notes that abandoned heap bytes can reach swap and
core dumps; that reach is not something this harness measures.

**Build-dependence: how many blocks a run abandons is a property of the build, not of the
source.** Whether a given `Vec` operation abandons a block at all depends on the allocator and
on heap layout at that moment — §2 makes the same point about "may" being load-bearing — and
optimization level changes how many intermediate buffers exist to abandon at all. In the
harness this one was ported from (msoffice-crypto, branch `experiment/zeroizing-alloc`, closed
unmerged 2026-09-18) one workload released 405 dirty blocks at `--release` against 521 at
opt-level 0. That figure is carried here with its source and has **not** been reproduced in
this repository; it is cited for the shape of the effect, not as a number about this harness.
The consequence for reading results is concrete: the assertions here are `>=` on the
planted-pattern count and `> 0` on the block count, never equality against a remembered figure,
and a block count that differs between two runs is not by itself evidence that anything
changed.

**No third-party crate is characterised here beyond what these artifacts measure.** What this
repository says about `zeroizing-alloc` is bounded by them: the wipe covers the blocks §2's
hazard abandons, including the reallocation-abandoned ones, and it survived the PGO + fat LTO
configuration the receipt records. Nothing beyond that, in either direction.

## What the runtime harness cannot prove

**Optimizer survival.** The volatile read that makes the observation possible is exactly what
keeps the store it observes live. A runtime probe of this shape is therefore not merely silent
about dead-store elimination — it is *structurally incapable* of detecting it. `cargo test` is
opt-level 0 besides.

This matters because the claim a reader takes from §2 is the survival claim, and the three
runtime binaries do not support it. What they support is narrower and worth having on its own:
*a zeroizing global allocator wipes the blocks §2's hazard abandons, including the
reallocation-abandoned ones.* The two are not the same sentence and must not be merged into
one.

The survival question is answered separately, by different artifacts:

- `tools/pgo_allocator_compare.sh` builds the same program under `-Cprofile-use` with
  `lto = "fat"` and `codegen-units = 1`, and then tries to read a freed block back. It is
  hand-run, wired into no CI job, and refuses to run outside Linux/glibc — deliberately. The
  readout depends on the allocator handing the just-freed block straight back, which glibc does
  and the Windows heap does not; and on Windows `HeapFree` is not a deallocation function LLVM
  recognises, so a fill before it is never proven dead. A green Windows number would be
  consistent with the mechanism working *and* with it not, which is why the script prints a
  refusal instead of a figure.
- `docs/design/receipts/` holds the captured stdout — raw output rather than transcribed
  figures — with a README recording, per file, the toolchain, whether a control fired in the
  same output, and the outcome. Cite figures from the captures, not from prose that quotes
  them.

Two reading rules the receipts README states, which anyone citing from here inherits:

- **An attempt where the attack never engaged is inconclusive**, not a pass. Indirect-call
  promotion declines any call site that is not hot enough by the profile summary's cutoff and
  emits no remark when it declines, so a run that recovers nothing may mean the wipe held or
  may mean nothing happened at all. A clean subject counts only when the same run has shown the
  attack works.
- **A synthetic control is a property of that control and of nothing else.** The control
  constructs in those runs were written to be recoverable, to establish that the probe can see
  residue at all. Their rows do not compose with any other row into a claim about a released
  crate.

## Running it

The three binaries are auto-discovered by Cargo; `test`, `test-release` and the `msrv`
`--all-targets` check pick them up with no workflow edit. They are gated
`#![cfg(all(feature = "alloc", not(miri)))]` — `alloc`, not `std`, because a test binary links
`std` regardless of the library's features and gating on `std` would cut them out of almost
every matrix row; `not(miri)` because `fuzz-miri.yml` runs
`cargo miri test --workspace --all-features`, and an intercepted global allocator is not
something to run under Miri.

```sh
cargo test --features=full \
  --test heap_residue --test heap_residue_nowipe --test heap_residue_wiped -- --nocapture
```

Expect the two controls to report the planted pattern, the subject to report none, and a
non-zero block count and a zero foreign-deallocation count in all three. Block counts that
disagree badly between the three binaries mean the configurations have diverged in something
other than their allocator, which is the one thing they are supposed to share.

`examples/zeroizing_alloc_app.rs` is the copy-paste application shape from §2 made executable,
so the one piece of that section's advice CI could not otherwise check is compiled — it is
reached by the `msrv` job's `cargo +1.85 check --workspace --all-features --all-targets`.
Nothing here ships: `include` in `Cargo.toml` lists only `src/**/*.rs` and the top-level
documents, so `tests/`, `examples/`, `tools/` and `docs/design/` stay out of the published
tarball.
