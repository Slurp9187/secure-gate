# PR #182 → `release/0.8` backport ledger

Companion to [`pr-182-impl-audit.md`](pr-182-impl-audit.md). Every change made while
addressing that audit is classified here as it is made, so the final 0.8 backport is a
worklist rather than an archaeology exercise.

`release/0.8` received the same content in the earlier backport (#176 / #178 / #179 /
#181), so most of #182's doc, changelog and CI corrections describe text that exists on
0.8 too. Anything fixed only on `main` silently re-diverges the branches.

**Verified against `origin/release/0.8`**, not assumed — the "on 0.8?" column records an
actual `git show origin/release/0.8:<path> | grep` result.

## Constraints that override a straight cherry-pick

- 0.8 is an **LTS on MSRV 1.70, edition 2021**. Never port a dependency or toolchain bump.
- 0.8's rustdoc job is pinned to **1.70** because of the grouped-`use` ICE; main's is
  `stable`. CI changes need re-deriving, not copying.
- 0.8 keeps `#[cfg(feature = "std")] impl std::error::Error`; main uses unconditional
  `core::error::Error`. Do not let error-handling prose cross over.

## Ledger

| # | Change | On 0.8? | Port? | Note |
|---|---|---|---|---|
| 1 | Root README: compat row said "Published as … crates.io" | yes | **yes** | Same table, same link |
| 2 | Compat `documentation = docs.rs/...` removed; root README docs.rs link | yes | **yes** | 0.8 also lacks `publish = false` — port that too (it is a #182 change, not audited) |
| 3 | Install snippets → git dep (compat README, MIGRATING) | yes | **yes** | 0.8 snippets read `version = "0.8"`; use the git form, not a version |
| 3b | Core README crates.io compat link | **no** | check | 0.8's core README phrases this differently — inspect before editing |
| 4 | `v08.rs` / `v10.rs` migration steps 1 & 5 named `secure-gate` | yes | **yes** | Both files, both steps |
| 5 | `secrecy-compat` "enables the modules" claim (mod.rs + compat README) | yes | **yes** | 0.8's `Cargo.toml` comment may still be the old wording — check |
| 6 | `mod.rs` `CloneableSecret` label/target mismatch | yes | **yes** | |
| 7 | `v10.rs` table `CloneableSecret` → `secure_gate::CloneableSecret` | yes | **yes** | Confirm 0.8 gates `cloneable` the same way |
| 8 | `mod.rs` `crate::SerializableSecret` → `secure_gate::…` | yes (×2) | **yes** | |
| 9 | `RevealSecret` "byte-length metadata" → `SecretLen` | yes | **yes** | 0.8 **does** have `SecretLen` (`lib.rs`), so the fix applies verbatim |
| 10 | Root CHANGELOG overclaimed the rustdoc job "matches docs.rs" | n/a | no | 0.8's changelog has its own rustdoc wording — re-check, do not copy |
| 11 | *(refuted)* README/ci.yml wording already correctly scoped | — | no | No change was made |
| 12 | Core CHANGELOG "no other build sets docsrs" self-contradiction | n/a | no | Text is main-only |
| 13 | `lib.rs` comment named the removed `doc_auto_cfg` gate | n/a | **no** | Main-only — the attribute does not exist on 0.8 |
| 14 | Root CHANGELOG missing the `doc_cfg` entry | n/a | no | Main-only |
| 15 | "thiserror removed from both crates" — core only this cycle | n/a | check | 0.8 dropped thiserror in its own backport; verify its wording |
| 16 | "ships in the published tarball" vs `publish = false` | yes | **yes** | Port with the `publish = false` change |
| 17 | Nightly docs.rs step made blocking, `-D warnings` dropped | no | **no** | 0.8's rustdoc job is pinned to 1.70 for the ICE; no nightly step to make blocking |
| 18 | compat `fuzz/` `.to_string()` → `into_inner()` | **no** | n/a | 0.8 has no compat `fuzz/` crate |
| 19 | compat fuzz triggers widened | no | n/a | Same — no compat fuzz on 0.8 |
| 20 | `fuzz-quick.yml` builds compat fuzz targets | no | n/a | Same |
| 21 | compat `serde-serialize` / `serde-deserialize` lint rows | absent | **yes** | `ci-0.8.yml` has no such rows — re-derive, do not copy the YAML |
| 22 | compat runtime tests in debug, not release-only | absent | **yes** | `ci-0.8.yml` does not run compat tests at all — check before adding |
| 23 | `proptest_suite` gated on this crate's `alloc` | **yes** | **yes** | 0.8 has the identical gate, so the same suite is being skipped there |
| 24 | `cargo test` lines missing `-p secure-gate-compat` | yes (3×) | **yes** | Scoping, not a fix: the bare form works on 1.85/1.97/1.98 — the audit's "virtual workspace makes it fail" premise is wrong. Without `-p` it just runs every member |
| 25 | README "20 feature combinations" → 19 | no | n/a | 0.8's README has no such count; its own matrix differs |
| 26 | `full` documented as "Everything" (omits `std`) | yes (both) | **yes** | Confirm 0.8's `full` definition first — it may differ |
| 27 | "no const-generic arrays" — v08 uses them | yes | **yes** | |
| 28 | compat fuzz target deref style | no | n/a | No compat fuzz on 0.8 |
| 29 | README layout missing compat `fuzz/` | no | n/a | Directory does not exist on 0.8 |
| 30 | `exclude` names both fuzz crates | no | n/a | 0.8 has no compat fuzz to exclude |
| 31 | `SECURITY.md` "Last updated" stamp | yes | **yes** | Stamp with the 0.8 rc, not rc.9 |
| 32 | PR description refresh | — | no | Process, not code |
| 33 | *(refuted)* second rustdoc step with deps | — | no | docs.rs documents only the target crate; `--no-deps` is closer to what ships |

### Known main-only (do **not** port)

- `#![cfg_attr(docsrs, feature(doc_cfg))]` and the docs.rs feature badges. The gate is
  nightly-only and the surrounding story assumes main's toolchain; 0.8's rustdoc job is
  pinned to 1.70 for the ICE. Revisit only if 0.8 ever gains a nightly docs job.
- Anything naming edition 2024 or MSRV 1.85.
