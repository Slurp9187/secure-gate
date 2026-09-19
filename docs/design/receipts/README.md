# Receipts: captured evidence for the zeroizing-allocator remedy in `SECURITY.md` §2

`SECURITY.md` §2 documents a hazard this crate cannot fix from inside a library — a
capacity change through `with_secret_mut` / `expose_secret_mut` reallocates outside
`secure-gate` and the abandoned block is freed with the secret still in it — and points at
the one remedy only the final binary can apply: a zero-on-deallocate global allocator.

Section 2 quotes numbers for both halves of that: the residue the hazard leaves, and what an
allocator's wipe does to it. **Those numbers were transcribed, not captured.** A transcribed
figure is a claim that was true when it was typed, and a reader cannot tell it apart from one
typed wrong. This directory holds the raw stdout instead, so the figures in §2 can be checked
against the runs they came from rather than taken on trust.

## The rule this directory is curated by

**Measurements travel; verdicts do not.**

What is here is captured output: a command line, a toolchain, and what the program did.
Review rounds, their conclusions and their characterisations of any third-party crate are
**not** re-homed here in any form. A review's verdict about someone else's crate is not
evidence, and carrying one into this repo would put it under this repo's name where it would
outlive anyone able to correct it.

## How each file is graded

Not every attempt at defeating an allocator's wipe is a result. The attack these runs use is
**indirect-call promotion under PGO**: the optimizer turns an indirect call direct, inlining
follows, and dead-store elimination is then entitled to delete a fill that sits immediately
before a deallocation. That attack can silently decline to engage — promotion refuses any call
site that is not hot enough by the profile summary's cutoff and emits no remark when it
refuses — so a run that recovers nothing may mean the wipe held, or may mean nothing happened
at all.

Each entry below therefore states **whether the attack engaged**, evidenced within the same
output either by a `pgo-icall-prom (success)` remark or by a control actually recovering the
planted pattern. **An attempt where promotion never fired is INCONCLUSIVE, not a pass, and is
labelled that way.** A clean subject counts only when the same run has shown the attack works.

Two reading notes that apply throughout:

- `same_block=true` / `same=true` is **load-bearing**. It says the allocator handed back the
  block that had just been freed, so the bytes read are the bytes that were in it. A `0/16`
  with `same=false` means a different block was read and proves nothing either way.
- The read window starts past the head of the block. The first bytes of a freed glibc chunk
  are the allocator's own free-list links, not payload; sampling them is an easy way to
  measure nothing and conclude there is no hazard. The two probe families here pick
  different windows: the **PGO probes sample 16 bytes starting at offset 16**; the
  **section-2-shape probes sample 4032 bytes starting at offset 64**. Each number is a
  **window size chosen by that probe**, and nothing else. They are not two readings of one
  block, and no arithmetic relates one to the other.

---

## Files

### `00-env-linux.txt`

- **What it measured:** nothing — it is the environment capture, and it is the toolchain
  provenance for every 1.85.1 run in this directory.
- **Date:** 2026-09-17 07:51:59 UTC.
- **Toolchain:** `rustc 1.85.1 (4eb161250 2025-03-15)`, commit-hash
  `4eb161250e340c8f48f66e2b929ef4a5bed7c181`, LLVM 19.1.7, host
  `x86_64-unknown-linux-gnu`, `cargo 1.85.1`; glibc 2.39 (Ubuntu 2.39-0ubuntu8.8),
  Linux 6.18.33.2-microsoft-standard-WSL2, 8 CPUs, Intel i7-10510U.
- **Control in the same output:** n/a.
- **Outcome:** n/a. Cite this file whenever a capture below does not restate its own toolchain.

### `2026-09-18-pgo-fat-lto-rustc-1.96.1.txt`

- **What it measured:** four allocator configurations under PGO (`-Cprofile-use`) + fat LTO +
  `codegen-units=1`, each planting a pattern in a block, freeing it, requesting it straight
  back and counting how many of 16 pattern bytes survived. Rows: `none` (no allocator),
  `strawman` (a **synthetic** fn-pointer construct written for this comparison — not a
  released crate), `onepass` (reported as `zeroizing-alloc` 0.1.1 — see the mapping bullet
  below), `sgza` (`secure-gate-zalloc`). The row mapping is stated in the file's header
  rather than inferred from the row names.
- **Date:** 2026-09-18. Produced by a **four-configuration variant** of the msoffice-crypto
  comparison harness, on branch `experiment/zeroizing-alloc` (PR #19, closed unmerged the
  same day). **That variant's script is held in no tree available here** — not in this
  repository, not in the msoffice-crypto worktree at `d2b0f25`, and not in
  `secure-gate-zalloc`: the row names above and the `RECOVER size=… hits=… same=…` line
  format appear in no file in any of those trees, `onepass` least of all.
  `tools/pgo_allocator_compare.sh` in this repository is the **three-configuration** form of
  the same method — rows `none` / `fnptr_no_ptr_barrier` / `zeroizing_alloc`, printed as
  `size=64    recovered=16/16  same_block=true`. It is the method, not the origin of this
  capture, and re-running it will not reproduce these rows line for line. The stdout is held
  here because the script and the branch's working tree are both gone.
- **The `onepass` → `zeroizing-alloc` 0.1.1 mapping is reported, and cannot be checked
  against anything held here.** Its source is a message in the orchestrating session,
  relaying the msoffice-crypto session's report that the harness script declared
  `zeroizing-alloc = "0.1.1"` as the `onepass` dependency. That is a session message rather
  than a captured artifact, and the script it describes is in none of the trees named above,
  so the mapping cannot be re-verified from any file. It is recorded here with its source
  attached rather than asserted bare, and every `onepass` row carries that qualification.
- **Toolchain:** `release: 1.96.1`, `llvm-profdata` from the matching stable sysroot.
- **Control in the same output:** **yes, two.** `none` recovered 16/16 at both block sizes,
  `same=true`. `strawman` recovered 16/16 at both sizes, `same=true`, in the second block.
- **Did the attack engage?** **Yes** — both controls recovered the full pattern in the same
  configuration.
- **Outcome:** `onepass` 0/16 and `sgza` 0/16, at both 64 and 4096 bytes, `same=true` on every
  row.
- **Read the header before citing this file.** `strawman: BUILD FAILED (gen)` in the first
  block is a **harness defect, not a result** — the probe's `Cargo.toml` was written into the
  strawman library's directory and clobbered it. The second block is that leg re-run correctly.
  **Cite both blocks together**; the first alone reads as a table with a hole where a control
  should be.

### `48-recover-linux.txt`

- **What it measured:** the same recovery method, reached through the **cargo** flow with
  `[profile.release] lto = "fat"` rather than a hand-rolled `rustc` recipe — which is what makes
  the callee resolvable at promotion time, and what the instrumented build must match. Four
  rows: a control and the subject, each with and without PGO, at 4096 bytes (64-byte figures in
  parentheses). The subject row is labelled `this crate`: the crate the test lives in,
  `secure-gate-zalloc`, at commit `13fe5e2`.
- **Date:** 2026-09-17 18:13:26 UTC.
- **Toolchain:** not restated in the capture. `00-env-linux.txt` records rustc 1.85.1 /
  LLVM 19.1.7 on the same host earlier the same day.
- **Control in the same output:** **yes, and mandatory** — the test is written so that a
  control which does not fire fails the run rather than letting it abstain.
- **Did the attack engage?** **Yes** — `control, PGO+fat LTO` recovered **16/16**,
  `same_block=true`, at both block sizes.
- **Outcome:** subject 0/16, `same_block=true`, under PGO + fat LTO and again without PGO.
- **Scope, so it is not overclaimed later:** this is **fat LTO through cargo**, not every LTO
  mode through cargo. The `control, no PGO` rows are the configuration where the attack is not
  expected to engage; the 64-byte one reads `same_block=false` and therefore reports nothing in
  either direction.
- **Independence:** this is a reproduction written from a *description* of the method, not by
  reusing the msoffice-crypto harness. Together with the 1.96.1 run above that makes **two
  independent runs, not three** — and the second is worth citing precisely because the
  harnesses differed.

### `45-hazard-final.txt` + `46-hazard-ours.txt` — cite as a pair

These two are one item. `45` demonstrates the hazard; `46` is the same driver, same toolchain,
against `secure-gate-zalloc`'s design. Neither file measures any released third-party crate.

**`45-hazard-final.txt` — the hazard, with its controls**

- **What it measured:** nine configurations — three call shapes (**A** wipe in the binary
  crate, **B** cross-crate with the callee exported, **C** cross-crate with the callee private)
  × three LTO modes (`fat`, `thin`, `false`) — against a **synthetic** fn-pointer wipe
  construct built for this driver (`probe_a::clear_bytes`, `wiper_C::clear_bytes`). Each
  configuration reports a no-PGO control, the `pgo-icall-prom` remarks, the PGO result and the
  emitted IR at the deallocation site.
- **Date:** 2026-09-17 16:59:12 UTC (stamped in the file).
- **Toolchain:** `rustc 1.85.1 (4eb161250 2025-03-15)`, via `RUSTUP_TOOLCHAIN=1.85` in
  `_hazard_final.sh`.
- **Control in the same output:** **yes** — a no-PGO control per configuration.
- **Did the attack engage?** **In 4 of 9 configurations.** A/`fat` and A/`false` carry
  `pgo-icall-prom (success): Promote indirect call … 600000 out of 600000` **and** recovered
  16/16 at both sizes. B/`fat` and C/`fat` recovered 16/16 at both sizes even though their
  remark reads `(missed): Cannot promote indirect call: target … not found` — the residue was
  demonstrated by measurement there regardless of the remark.
- **INCONCLUSIVE:** four of the remaining five — B/`thin`, B/`false`, C/`thin` and C/`false`
  all carry a `(missed)` remark, promotion did not fire, and nothing was recovered. Those are
  attempts that did not engage, and they are a clean bill of health for nothing. The fifth,
  A/`thin`, is the one exception in the other direction: promotion fired and 0/16 came back at
  4096 bytes with `same_block=true`, so it is an engaged attempt that found no residue — in
  the synthetic construct, at that one configuration. (Its 64-byte reading is
  `same_block=false` and therefore reports nothing either way.)
- **Outcome:** the residue hazard is real and reproducible under PGO with a fn-pointer wipe, in
  this repo's own terms, with controls in the same output. That is a property of the synthetic
  construct this driver builds and of nothing else.

**`46-hazard-ours.txt` — the same driver against `secure-gate-zalloc`**

- **What it measured:** the same three LTO modes against `secure-gate-zalloc` at `main b186c53`,
  with the no-PGO control, the promotion remarks, the PGO result, and the IR at the
  deallocation site.
- **Date:** not stamped in the capture; produced 2026-09-17, ~17:02 UTC, by `_hazard_ours.sh`,
  minutes after `45`.
- **Toolchain:** `RUSTUP_TOOLCHAIN=1.85` in `_hazard_ours.sh`; `00-env-linux.txt` pins that to
  1.85.1 / LLVM 19.1.7 on this host.
- **Control in the same output:** **yes** — a no-PGO control per LTO mode.
- **Did the attack engage?** **Not applicable, and that is why this file is cited with `45`.**
  The capture records `0 icall-prom lines (nothing to promote in this design)`: the indirect
  call promotion needs is absent by construction, so the attack's precondition is missing
  rather than its engagement being missed. **On its own this file does not show an engaged
  attack.** What makes it meaningful is `45`: the same driver, same toolchain, minutes earlier,
  demonstrably capable of recovering 16/16 from a fn-pointer construct.
- **Outcome:** 0/16 at 64 bytes and 0/16 at 4096 bytes, `same_block=true`, in all three LTO
  modes, with and without PGO. The IR excerpts show two zeroing memsets, volatile stores and
  `asm sideeffect` barriers taking the block's own pointer as an operand, ahead of `free`.

### `49-secure-gate-shape-linux.txt`

- **What it measured:** **`secure-gate`'s own §2 shape**, not a synthetic one — a 4 KiB secret
  grown one byte past its capacity through `with_secret_mut`, with a neighbour behind it so the
  reallocation has to move (`moved: true`), and the abandoned block requested back and read.
  Run at `secure-gate-zalloc` commit `2434dfa`, whose subject records the fix that made the
  readout sample payload rather than the allocator's own bookkeeping.
- **Date:** 2026-09-17 19:26:44 UTC.
- **Toolchain:** not restated in the capture; see `00-env-linux.txt` (rustc 1.85.1, glibc 2.39,
  WSL2), same host, same day.
- **Control in the same output:** **yes** —
  `without_the_allocator_the_abandoned_buffer_still_holds_the_secret` is the same shape with no
  allocator installed, in the same run.
- **Did the attack engage?** n/a — this is not a compiler attack. What has to be shown is that
  the residue is **there to find**, and the control shows it in the same output.
- **Outcome:** with the allocator installed, `readout: 0/4032 pattern bytes, 8 non-zero of
  4096, same block back: true`, and the pinned block was seen at the inner allocator all zero.
  Without it, `readout: 4032/4032 pattern bytes, 4072 non-zero of 4096, same block back: true`.
  **That 4032-of-4032 is the figure `SECURITY.md:223` quotes** — here it is captured, with its
  control, in one run.

### `50-rebased-branch-linux.txt`

- **What it measured:** the same two tests as `49`, re-run at commit `5ef4f5a` after the rebase.
  Its job is to show the `49` figures were not an artifact of the pre-rebase tree.
- **Date:** 2026-09-17 19:43:16 UTC.
- **Toolchain:** as `49`; see `00-env-linux.txt`.
- **Control in the same output:** **yes** — the same no-allocator test.
- **Outcome:** identical figures at different addresses: `0/4032` with the allocator
  (8 non-zero of 4096), `4032/4032` without (4072 non-zero of 4096), `same block back: true`
  on both. Full suite green, clippy 0, fmt ok.

---

## What this set does and does not support

What these receipts support, stated at the width the measurements actually cover:

- The §2 hazard is real and reproducible in `secure-gate`'s own shape, with a control:
  **4032 of 4032 payload bytes recovered** from the abandoned block with no allocator installed
  (`49`, `50`).
- A zero-on-deallocate allocator removes it in that same shape: **0 of 4032**, same block back
  (`49`, `50`).
- The general worry about such a wipe — that it is a dead store before a deallocation, and that
  PGO + LTO can promote an indirect call, inline, and delete it — **does happen** to a
  fn-pointer wipe with no barrier: 16/16 recovered, with promotion remarks and IR to show for
  it (`45`, and the `strawman` and `none` controls in the 1.96.1 run).
- In the PGO + fat LTO + `cgu=1` configuration where those controls fired, neither the
  `onepass` row (reported as `zeroizing-alloc` 0.1.1) nor the `sgza` row
  (`secure-gate-zalloc`) left the pattern behind: **0/16**, `same=true`, at both block sizes
  (`2026-09-18-pgo-fat-lto-rustc-1.96.1.txt`). `48` reproduces that independently through
  the cargo fat-LTO flow **for `secure-gate-zalloc` only** — its subject row is labelled
  `this crate`, which is `secure-gate-zalloc` at `13fe5e2`, not `zeroizing-alloc`. No run
  held in this directory measures `zeroizing-alloc` a second time.

What they do not support, and must not be stretched to:

- **A synthetic control being defeated says nothing about any released crate.** The `strawman`
  row and `45`'s `probe_a` / `wiper_C` constructs were written to be defeated, to prove the
  measurement can detect residue at all. Their results are a property of those constructs. They
  do not compose with any other row into a claim about a crate.
- **Fat LTO through cargo is not every LTO mode through cargo** (`48`).
- **A run where promotion did not fire is inconclusive** — five of `45`'s nine configurations,
  and any hand-rolled `rustc` recipe whose remarks read `Cannot promote indirect call`. It is
  not a pass, and it is not a failure.
- Nothing here measures `secure-gate` itself. `secure-gate` is `#![forbid(unsafe_code)]` and
  cannot install an allocator; these runs are addressed to the application author who can.

## Deliberately not held here

**Large IR and assembly dumps.** Recorded rather than copied, so their absence is explicit
rather than silent. All five live in the untracked, machine-local
`O:\projects-github-clones\zeroizing-alloc-fork\reviews\` and are in no commit on any branch or
remote:

| File | Bytes | SHA-256 |
|---|---|---|
| `gpt-boundary-rustabi-fat.ll` | 15,229,801 | `364f000289d92dbef1ff67514181be12e7b2165db8b3ad140effbde321d136c0` |
| `fable-driver_fat.ll` | 3,452,022 | `4d899b510736c171d083113734c00834fff41ed99f82db6483f35d4b2f783de3` |
| `gpt-windows-native-unwind.s` | 2,028,813 | `a40c8f9817b4761b64623b7f0ce2c923a4b304b5ec0a51392d17da8e9ff29f4c` |
| `gpt-windows-s-generic-unwind.s` | 1,986,501 | `068f574ac23fd83112261760d002ad7f5425a5092526d59506cd2e0c88477bbf` |
| `gpt-windows-z-generic-abort.s` | 1,928,640 | `3888376dc6aa54a0d85decda91bb272843555670b896a33961f381e4cdb761d6` |

They are excluded for size alone. The IR that actually carries the argument — the deallocation
sites, the promotion remarks and the guarded calls — is quoted inline in `45` and `46`, which
is the part a reader needs.

**Review documents and their conclusions**, from every round and every reviewer. Excluded by
the rule at the top of this file, not by size: measurements travel, verdicts do not.

**Claims with no receipt in this directory.** The wider record describes further attempts —
an 18-configuration sweep on 1.97.0, an out-of-line `__rust_dealloc` shape, a functional
three-way against a real workload, and a hand-rolled `rustc` recipe across every LTO mode that
recorded `icp_guards=0` and a `Cannot promote indirect call` remark and is **inconclusive** by
its own record. Their stdout is not here. Do not cite figures for them **from this directory**;
citing them from here would recreate exactly the transcription problem this directory exists to
fix.

## Provenance of the copies

Every `.txt` other than `2026-09-18-pgo-fat-lto-rustc-1.96.1.txt` was copied byte-for-byte,
unedited, from `C:\Users\chadm\Projects\secure-gate-zalloc\docs\reviews\receipts-2\`, where the
`_*.sh` drivers that produced them also live. Filenames are unchanged so a citation resolves in
either tree.

| File in this directory | Bytes | SHA-256 |
|---|---|---|
| `00-env-linux.txt` | 405 | `5965f0ad87b14a17efc95025c37782df8409d662f489d1ca618725092a4504f1` |
| `45-hazard-final.txt` | 13,332 | `91f271fe268d903b7692582cd2aa15964f77a9525d7b25664e5868a4d9261514` |
| `46-hazard-ours.txt` | 3,393 | `d43fd87000944b3f1f65da9edf453455e256715bc7ce62b271b98c7b0d37de38` |
| `48-recover-linux.txt` | 691 | `0850e8c3478e5f83b52238b9ff9d2abeacce8442962d3c672959fed925df032f` |
| `49-secure-gate-shape-linux.txt` | 1,766 | `90ca29b2890224c14740a2258e1f046d8737c8c634d5d04319fabc2316edcb33` |
| `50-rebased-branch-linux.txt` | 1,755 | `6143f45e0e9e5dd2fed036e6f8e81037c558fc5fd88cdd78d4d847a38ca09b42` |

`2026-09-18-pgo-fat-lto-rustc-1.96.1.txt` is a header plus two verbatim output blocks; the
branch that produced the stdout is closed and the working tree is gone, so the blocks are the
artifact.

## Checksums

Verification of all files present in this directory:

| Filename | Bytes | SHA-256 |
|---|---|---|
| `00-env-linux.txt` | 405 | `5965f0ad87b14a17efc95025c37782df8409d662f489d1ca618725092a4504f1` |
| `2026-09-18-pgo-fat-lto-rustc-1.96.1.txt` | 5579 | `20758ec01c5d9c6da811fa1a4d4225913ce2bc60471d24af23c023afabca53ea` |
| `45-hazard-final.txt` | 13332 | `91f271fe268d903b7692582cd2aa15964f77a9525d7b25664e5868a4d9261514` |
| `46-hazard-ours.txt` | 3393 | `d43fd87000944b3f1f65da9edf453455e256715bc7ce62b271b98c7b0d37de38` |
| `48-recover-linux.txt` | 691 | `0850e8c3478e5f83b52238b9ff9d2abeacce8442962d3c672959fed925df032f` |
| `49-secure-gate-shape-linux.txt` | 1766 | `90ca29b2890224c14740a2258e1f046d8737c8c634d5d04319fabc2316edcb33` |
| `50-rebased-branch-linux.txt` | 1755 | `6143f45e0e9e5dd2fed036e6f8e81037c558fc5fd88cdd78d4d847a38ca09b42` |
