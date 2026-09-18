# `zeroizing-alloc` under PGO: what was measured, and a correction

**Correction of record.** The commit message of f6b6973 (#257) said of
`zeroizing-alloc`: *"That dependency was tested and
failed."* **That claim is not supported by the evidence.** The crate was never shown to fail.
A merged commit message cannot be edited, so the correction lives here and in a comment on #257.

This file exists because the claim was public, permanent, and about a third party's shipped code.
It records what was actually measured so that nobody has to reconstruct it from a conversation.

## What was claimed

That `zeroizing-alloc` defended its wipe through a function pointer loaded with `read_volatile`,
and that under profile-guided optimization with LTO the wipe was deleted — measured against the
published crate.

## What the record shows

Measurements were taken against **published artifacts**: the harness copies its subjects out of
`~/.cargo/registry/src/*/zeroizing-alloc-0.1.0/src/lib.rs` and `-0.1.1/`, so they are the
crates.io releases rather than reconstructions. On rustc 1.85.1 across `lto=none`, `thin` and
`fat`:

- **Promotion never fired.** Every row reports `icp_guards=0` with the call still indirect.
  Nothing was promoted, so nothing was inlined and nothing was deleted. The wipe ran.
- **The compiler said why**, in all three modes:
  `pgo-icall-prom (missed): Cannot promote indirect call: target with md5sum … not found`,
  alongside `clear_bytes definitions in module: 0` and `WIPER` resolving to
  `external global ptr`. The callee lived in another crate and the pass could not see it.
- **The run designed to fix that name mismatch produced no data.** It failed with
  `couldn't read …/za-0.1.0.rs: No such file or directory`, because the script had removed its
  own working directory.

A missed promotion is an **inconclusive attack, not a clean bill of health.** The honest summary
of those runs is *"we could not make it fail, and the one run designed to try properly errored
out"* — not *"it failed."*

## What is supported

- **The mechanism is real.** A wipe reached only through a function pointer does lose its fill
  under PGO with fat LTO. Demonstrated on a *constructed* wipe of that shape, reproduced on two
  toolchains, in a harness whose controls fired: `control_plain` and `control_null_barrier` lose
  the fill, `control_asm_block` keeps it.
- **The published crate holds.** On rustc 1.96.1 / LLVM 20, with a control firing at 16/16 in the
  same run, published `zeroizing-alloc` 0.1.1 recovered 0 of 16 bytes at both 64 B and 4096 B.
  No known defect.
- **0.1.1 adds a further barrier** — a volatile reload of the block pointer — on top of the
  indirection. The error that produced the original claim was composing *"a function-pointer wipe
  fails"* with *"that barrier fails alone"* into *"the crate using both fails."* That does not
  follow, and it was not measured.

## The "48 of 64 bytes" figure

Inherited from an earlier session and attributed to upstream commit `0f988e7`. No receipt for it
exists and that hash appears nowhere in the measurement record. **Do not rely on it.**

## What is unaffected

`SECURITY.md` §2 and `README.md` name no allocator. They state a property a reader can check —
prefer a wipe of volatile stores, which LLVM's LangRef forbids the optimizer from removing, or a
fill held by an inline-assembly barrier taking the block's own pointer — and ask whether a
project demonstrates that under PGO and LTO. `zeroizing-alloc` 0.1.1 meets it.

The 4032-of-4032 hazard figure in §2 is also unaffected: it was taken with **no allocator
installed**, so it measures this crate's own hazard and depends on nobody's implementation.

## Lesson

Naming a crate in a security document creates a dependency on that crate's ongoing correctness.
Condemning one by name creates a dependency on the condemnation being right. Both need the same
standard of evidence, and a measurement of a *shape* is not a measurement of an *artifact* —
which is the same distinction that produced the error corrected here.

1Password responded to the original report and shipped 0.1.1 within a day.
