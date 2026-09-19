# secure-gate-residue-probe

A `GlobalAlloc` probe that answers one question about **your** program:

> When my program abandons a buffer, is the data still in the block that goes back to the
> allocator?

It plants a known byte pattern where you tell it to, watches every block as it passes through
`dealloc`, and counts how many occurrences of that pattern come back. It has **zero
dependencies** and knows nothing about any particular crate — you supply the workload, you
decide what the numbers have to be.

Typical reasons to reach for it:

- you handle secrets and want to know whether a capacity change (`push`, `resize`,
  `shrink_to_fit`, `String::insert`) leaves a copy in a block you no longer own;
- you have installed a wipe-on-free global allocator and want a measurement rather than a
  belief;
- you are reviewing someone else's claim that "nothing survives", and want to know what their
  harness could actually have seen.

It is a dev-dependency; nothing it does reaches your release binary.

```toml
[dev-dependencies]
# or: secure-gate-residue-probe = "0.1", once this is on crates.io
secure-gate-residue-probe = { path = "../residue-probe" }
```

## The three binaries you have to write

A `#[global_allocator]` is process-wide, so each configuration is its own test binary. You
need **three**. This is the part people skip, and skipping it is what makes the result
worthless.

| file | allocator | what it must assert |
| --- | --- | --- |
| `tests/residue_control.rs` | `Spy<System>` | the pattern **is** released — there is something to find |
| `tests/residue_nowipe.rs` | `NoWipe<Spy<System>>` | the pattern is still found **in the composed position** |
| `tests/residue_subject.rs` | `YourAlloc<Spy<System>>` | whatever you are measuring |

Put the workload in `tests/residue_support/mod.rs` — a subdirectory is not built as a test
target, so all three binaries include the same file and cannot drift apart. Each binary is
then that `mod` line and one `residue_binary!` invocation, which generates the
`#[global_allocator]` for its role and the single `#[test]` with that role's assertions. The
three differ in exactly one argument:

```rust
// tests/residue_control.rs
mod residue_support;
secure_gate_residue_probe::residue_binary! {
    control,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}

// tests/residue_nowipe.rs
mod residue_support;
secure_gate_residue_probe::residue_binary! {
    nowipe,
    workloads: residue_support::WORKLOADS,
    planted_len: residue_support::SECRET_LEN,
}

// tests/residue_subject.rs
mod residue_support;
use secure_gate_residue_probe::Spy;
use std::alloc::System;
secure_gate_residue_probe::residue_binary! {
    subject: YourAlloc<Spy<System>> = YourAlloc(Spy::new(System)),
    workloads: residue_support::WORKLOADS,
}
```

`workloads` is anything that iterates `(&str, fn())` pairs; `planted_len` is the byte length
you hand to `plant`, from which the floor the controls must reach is derived. A spy on an
allocator other than `System` takes `inner: Type = initializer` on the two controls. The
crate-level rustdoc has the support module written out and the macro's documentation shows
the hand-written form each invocation expands to; `cargo doc --open` and copy them. The
macro cannot make the three files one file — nothing can, for the reason above — it makes
each of them two lines.

### Why three and not two

Suppose the subject binary reports zero hits. That is consistent with three different worlds:

1. the wipe worked;
2. the blocks were never released — your workload did not do what you thought;
3. the probe is reading memory other than the memory it believes it is reading.

The control binary rules out (2). The no-wipe binary rules out (3): it has the subject's
composition and its `realloc` route, and differs from the subject in exactly one thing. A spy
reading the wrong position reports clean under the subject **and** clean there.

So the rule is blunt: **the no-wipe leg must report dirty, or the subject's zero means
nothing.** Assert it in the test. Do not print it and plan to read it later — nobody reads it
later.

`NoWipe` is a synthetic construct that exists for this and nothing else. It forwards
everything and does nothing, so what it reports is a property of that construct alone and says
nothing about any real allocator.

Quote all three binaries or none. A subject binary quoted on its own is not a result.

## Correctness rules you must not break

Each of these is the difference between a measurement and a number. They look like style and
will be tidied away unless the reasons travel with them — the reasons are in the rustdoc, so
read them before you change any of it.

1. **`Spy::realloc` is move-always.** It allocates, copies, and releases the old block through
   its own `dealloc`. It must never forward to the inner `realloc`: libc frees the old block
   inside C, where it never reaches `dealloc` at all, so a forwarding probe is structurally
   unable to see reallocation-abandoned blocks — which is usually the entire class of block
   you are looking for. A probe like that does not under-report; it reports zero.
2. **`NoWipe` leaves `realloc` to the `GlobalAlloc` default.** That is the route a wrapper
   which does not implement `realloc` actually takes, and a control has to release memory the
   same way the subject does.
3. **Read at offset 0, at the `dealloc` boundary, through `read_volatile`.** In this
   composition the inner allocator has not been told about the block yet, so no free-list
   links have been written into its first bytes. A probe that looks *after* free must skip a
   prefix, and a skipped prefix is where residue hides. If you reposition the spy, re-derive
   the offset instead of inheriting `0` as a constant.
4. **Never allocate inside `dealloc`.** Atomics and one `u64` on the stack. A logging line
   added here "just for debugging" recurses or deadlocks.
5. **One measuring thread.** The counters are process-wide. `measure` records the arming
   thread and routes every deallocation from anywhere else into `foreign_deallocs`; every
   binary must assert that count is zero. Do not rely on `--test-threads=1` — that is a fact
   about one invocation, not a property of your test suite, and bare `cargo test` in CI does
   not have it.

Also assert `blocks > 0` everywhere. Zero blocks with zero hits is a blind probe, not a clean
one.

## What this cannot prove

**It cannot detect optimizer elimination of a wipe.** The volatile read that makes the
observation possible is exactly what keeps a wipe's stores live — a store followed by a
volatile read is not a dead store. So this harness is not merely silent about dead-store
elimination; it is structurally incapable of detecting it, and no number of extra
configurations fixes that. `cargo test` is also opt-level 0 by default.

What the three binaries establish is that the blocks your workload abandons pass through the
allocator carrying, or not carrying, your pattern **in that build**. Whether a wipe survives
an optimizing build is a different question needing a different instrument — an optimized
build compared under PGO and LTO, or inspection of the emitted code. Keep the two claims in
separate sentences.

## API

- `Spy<A: GlobalAlloc>` — the probe. Generic, so `Spy(System)`, `Spy(Jemalloc)` and
  `Spy(MyArena)` all work. Install it **beneath** the allocator under test.
- `NoWipe<A: GlobalAlloc>` — the second control's composition, with no behaviour of its own.
- `residue_binary!` — one invocation per test file: `control`, `nowipe`, or
  `subject: Type = initializer`, plus `workloads:` and, for the controls, `planted_len:`.
  Generates that role's `#[global_allocator]` and its one `#[test]`.
- `measure(label, f) -> Measurement` — runs `f` with the probe counting and prints a line.
  What the macro calls; use it directly if your layout differs.
- `Measurement { blocks, blocks_with_pattern, pattern_hits, bytes_inspected, foreign_deallocs }`
- `PATTERN`, `plant(&mut [u8])`, `planted_hits(len)`, `count_pattern(&[u8])`, `is_armed()`

This crate contains `unsafe` — that is the point of it. It is `deny(unsafe_op_in_unsafe_fn)`
with a `SAFETY` comment on every block, and it does not, and cannot, weaken any
`forbid(unsafe_code)` guarantee of the crate you are measuring: it is a separate crate, used
as a dev-dependency, installed by your test binary.

## License

MIT OR Apache-2.0.
