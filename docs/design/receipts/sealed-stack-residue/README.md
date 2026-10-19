# Receipt: sealing-key and plaintext residue on the stack after a sealed access

`src/sealed/mod.rs` says the sealing key is recomputed on every access, wiped at the end of
it, and never stored, and that the plaintext temporary is wiped when the call returns. An
independent audit of PR #265 measured both claims false as first written, and the fix
(`scrub_stack`, and opening `SealedFixed` in place inside an `#[inline(never)]` frame) was
measured with the same probe. This directory holds that probe and its captured output.

## What is here

| File | What it is |
|---|---|
| `probe_stack.rs` | The probe, an integration test. It reads the stack with `unsafe` volatile reads and needs hooks that expose the sealing key, so it is kept here rather than in `tests/`. |
| `probe_hooks.patch` | The hooks: three `#[doc(hidden)]` methods that derive the key the way an access does. Applied to a scratch copy only; never part of the crate. |
| `runs.txt` | Captured stdout, before and after the fix, debug and release. |

## Method

Seal a `SealedFixed<32>` whose plaintext is a known pattern kept on the heap, so the test's
own frame holds no copy. Zero 96 KiB of stack by calling a function with a large frame. Make
one access through an `#[inline(never)]` helper. Then read the 48 KiB below the test's frame
and count occurrences of the 32-byte key (derived through the hooks after the measurement)
and of the plaintext.

Two controls keep a clean result from meaning "looked in the wrong place":

- **control**: a function that leaves a known pattern on the stack, then a snapshot. A hit
  shows the snapshot reaches stale stack. It reads 1 in release and 0 in debug, so the debug
  zeros below carry less weight than the release ones; the debug "before" run does find the
  key four times, which shows the debug snapshot reaches the region that matters.
- **baseline**: a snapshot after zeroing and before any access. It must read 0, or the probe
  is finding its own copies.

## Reproducing

From a checkout of the branch, in a scratch copy (`git archive HEAD | tar -x -C <dir>`):

```text
git apply docs/design/receipts/sealed-stack-residue/probe_hooks.patch
cp docs/design/receipts/sealed-stack-residue/probe_stack.rs tests/
cargo test --release --features sealed --test probe_stack -- --nocapture
```

The "before" rows come from commit `de02d62`, the last commit without the fix.

## What it does not cover

Only x86_64 Windows, rustc 1.98.1, was measured. Other targets use other ChaCha20 backends
and other frame layouts. Registers are not inspected. `SealedDynamic` was not probed: its
plaintext temporary is on the heap in a `Dynamic`, which wipes it, and its accesses end with
the same `scrub_stack`.
