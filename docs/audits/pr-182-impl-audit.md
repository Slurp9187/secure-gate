CI is green and the PR is mergeable. These are the remaining deltas.

---

## Blockers — `publish = false` was not followed through to user-facing docs

`secure-gate-compat` now refuses crates.io (`Cargo.toml:5`) and `https://crates.io/api/v1/crates/secure-gate-compat` is 404. Several surfaces still tell people to install it from crates.io / read it on docs.rs.

1. **`README.md:20`** — “Published as” still links `https://crates.io/crates/secure-gate-compat`. Change the column to unpublished / GitHub-only; drop the crates.io link.

2. **`README.md:98`** and **`secure-gate-compat/Cargo.toml:12`** — `documentation = "https://docs.rs/secure-gate-compat"` and the docs index still point at docs.rs. docs.rs will not build this crate. Point at GitHub rustdoc source, or drop the URL.

3. **Install snippets still use a crates.io dep**
   - `secure-gate-compat/README.md:15`
   - `secure-gate-compat/MIGRATING_FROM_SECRECY.md:56`
   - `secure-gate-core/README.md:386` (`https://crates.io/crates/secure-gate-compat`)
   
   Replace with a git/path dep, e.g. `{ git = "https://github.com/Slurp9187/secure-gate", package = "secure-gate-compat", features = ["secrecy-compat"] }`. Do not keep `version = "0.9"`.

---

## Should-fix — rustdoc still names the wrong crate / the wrong trait

4. **`secure-gate-compat/src/compat/v08.rs:42`** and **`v10.rs:33`** — Step 1 still says replace `secrecy` with `secure-gate` + `features = ["secrecy-compat"]`. That feature is on `secure-gate-compat`, not `secure-gate`. Same class as the `secure_gate::compat::` paths this PR claims to have fixed. Point at a git/path `secure-gate-compat` dep. Step 5 (“remove the `secrecy-compat` feature”) should say remove the `secure-gate-compat` dependency.

5. **`secure-gate-compat/src/compat/mod.rs:3`** and **`secure-gate-compat/README.md:34`** — still claim `secrecy-compat` “enables” `compat::v08` / `v10`. Those modules have no `cfg` on it and always compile. Match the corrected `Cargo.toml` comment: the feature turns on core features + `serde` and gates tests.

6. **`secure-gate-compat/src/compat/mod.rs:103`** — label is `secure_gate::CloneableSecret`; target is `crate::CloneableSecret` (the compat marker, always available). Clicking never leaves the compat trait. Target `secure_gate::CloneableSecret`.

7. **`secure-gate-compat/src/compat/v10.rs:28`** — table header is “secure-gate native” with “(with `cloneable` feature)”, but bare `[CloneableSecret]` resolves to `super::CloneableSecret` (compat, ungated). `v10.rs:53` imports `super::{CloneableSecret, ...}`. Point at `secure_gate::CloneableSecret` or drop the native/`cloneable` wording.

8. **`secure-gate-compat/src/compat/mod.rs:124-126`** — “Re-exports `crate::SerializableSecret` … same trait as … the crate root.” `crate` here is `secure_gate_compat`. The `pub use` is `secure_gate::SerializableSecret`. Link that, and say “secure-gate crate root.”

9. **`secure-gate-compat/src/compat/mod.rs:75-76`** — `ExposeSecret` rustdoc: “prefer `RevealSecret`, which additionally provides … byte-length metadata.” `len` / `byte_len` / `is_empty` live on `SecretLen` (`secure-gate-core/src/traits/reveal_secret.rs:303`), not `RevealSecret`. Drop “byte-length metadata” or name `SecretLen`.

---

## Should-fix — changelog / README overclaim the rustdoc job

The blocking job is stable, `--no-deps`, no `--cfg docsrs`. docs.rs is nightly, with deps, with `--cfg docsrs`. The nightly `--cfg docsrs` step is `continue-on-error: true` (`ci.yml:82-86`).

10. **`CHANGELOG.md:53-55`** — “matching what docs.rs builds.” Rewrite to: enforced contract is `--all-features -D warnings` on stable; docs.rs cfg is a separate nightly step.

11. **`README.md:109`** and **`ci.yml:54-55`** — same overclaim. Also mention: blocking toolchain is stable; `[package.metadata.docs.rs] rustdoc-args = ["--cfg", "docsrs"]` is not on the blocking job; the docs.rs cfg run is `continue-on-error: true`; `--no-deps` is not what docs.rs does.

12. **`secure-gate-core/CHANGELOG.md:499-512` vs `523-532`** — Testing bullet: job matches “the configuration docs.rs actually builds.” Documentation bullet: `--cfg docsrs` was dead, and the matching config is a non-blocking nightly step. Those cannot both stand. Narrow the Testing bullet to `all-features = true`. Line 529 (“no other build sets `docsrs`”) is immediately contradicted by lines 531-532.

13. **`secure-gate-core/src/lib.rs:7-12`** — comment says `` `doc_auto_cfg` annotates every feature-gated item `` while the attribute is `feature(doc_cfg)`. That is the rename this comment exists to stop. Name `doc_cfg`. Also “no other build sets `docsrs`” is false: `ci.yml:85` does.

14. **`CHANGELOG.md` rc.9 Testing** — root documented the rustdoc job, then `f2ef387` added `doc_cfg` / nightly `--cfg docsrs` and only core’s changelog absorbed it. Add a one-liner to root so the three changelogs agree.

15. **`CHANGELOG.md:48`** — “`thiserror` removed from both crates.” It existed only in core. Compat never had it. Say core only.

16. **`secure-gate-compat/CHANGELOG.md:64-67`** — “does ship in the published tarball via `include`” in the same rc.9 section that records `publish = false`. There is no published tarball. Say the file is in `include` but the crate is not published.

17. **`.github/workflows/ci.yml:82-86`** — the only rustdoc step that matches docs.rs (nightly + `--cfg docsrs`) is `continue-on-error: true`. A `doc_cfg` rename fails that step and still merges. Split it: blocking nightly smoke with `--cfg docsrs` and **without** `-D warnings` (hard errors only); keep `-D warnings` on stable. If you keep it non-blocking, stop naming the job `rustdoc – docs.rs feature set`.

---

## Should-fix — CI holes this PR’s own bugs would still slip through

18. **`secure-gate-compat/fuzz/src/arbitrary.rs:115`** — `encoded.to_string()`. `EncodedSecret` has no `Display`; this compiles via `Deref` → `str::to_string()`, which `encoded_secret.rs:52-65` calls the noisy extra copy and tells you to sweep. Core fuzz already does the named exit: `secure-gate-core/fuzz/src/arbitrary.rs:131` uses `encoded.into_inner()`. Use `into_inner()` here. Changelog text (“converts through Deref”) currently documents the footgun, not the API.

19. **`.github/workflows/fuzz-nightly-0.9-compat.yml:7-25`** — core `src`/`Cargo.toml` were added, but still no trigger on workspace `Cargo.toml`, `Cargo.lock`, or this workflow file. `fuzz-quick.yml` already watches those for core. A resolver/`[workspace.dependencies]` change, or a matrix typo in this YAML, can break compat fuzz with no PR run.

20. **`.github/workflows/fuzz-quick.yml`** — 90s smoke still covers only core fuzz even though it already watches `secure-gate-core/src/**`. Compat compile-break is gated only by the ~50 min × 4-job nightly-compat workflow (which did run on this PR). Add `compat_v08` / `compat_v10` as `cargo fuzz build` (or a short smoke) so an encoder rewrite fails in ~90s.

21. **`.github/workflows/ci.yml:88-115` (compat lint)** — rows are no-features / secrecy-compat / all-features. No `serde-serialize` only or `serde-deserialize` only row for `secure-gate-compat`. That is how “neither feature compiled on its own” survived this cycle. Core already has those rows (`ci.yml:201-205`). Add the two compat rows.

22. **`.github/workflows/ci.yml:234-242`** — debug `test` is `-p secure-gate` only. Compat runtime tests (including `proptest_compat`) run in `test-release` only. Add `cargo test -p secure-gate-compat --all-features` (debug), or the file this PR just made MSRV-visible still has no debug job.

23. **`secure-gate-compat/tests/proptest_suite/proptest_compat.rs:11`** — `#[cfg(all(feature = "secrecy-compat", feature = "alloc"))]`. Parent `proptest_suite/mod.rs:1` already requires `secrecy-compat`. `secrecy-compat` enables `secure-gate/alloc` but **not** this crate’s `alloc`, so `--features secrecy-compat --all-targets` still skips the file. That is why only `--all-features` compiled it. Either drop the extra `alloc` gate, or make `secrecy-compat` enable this crate’s `alloc`.

24. **`secure-gate-compat/MIGRATING_FROM_SECRECY.md:21-22`** and **`SECURITY.md:51`** — `cargo test --features secrecy-compat` with no `-p`. Virtual workspace; the correct form is already at `MIGRATING_FROM_SECRECY.md:281`. Add `-p secure-gate-compat`.

---

## Nits

25. **`README.md:107`** — “test (20 feature combinations)”. The `test` matrix is 19 rows (`ci.yml:141-220`). rc.8 had extra `encoding-bech32m` rows. Change to 19.

26. **`secure-gate-core/src/lib.rs:201`** and **`secure-gate-core/README.md:409`** — `` `full` | Everything `` / “All features combined”. `Cargo.toml:110` is `["alloc", "rand", "encoding", "ct-eq", "cloneable", "serde"]` — no `std`. CI comments call that deliberate. Say “everything except `std`.”

27. **`secure-gate-compat/src/compat/mod.rs:193`** — “Mirrors secrecy 0.8.0 (edition 2018, no const-generic arrays).” `v08.rs:98` uses const generics (`impl<T: fmt::Debug, const N: usize> DebugSecret for [T; N]`). Drop “no const-generic arrays.”

28. **`secure-gate-compat/fuzz/fuzz_targets/compat_v08.rs:94`** — `assert_eq!(*v08_arr_back.expose_secret(), arr)`. Same `*[u8; 32]` deref the MSRV fix just removed from `proptest_compat.rs:51`. Nightly-only, so not MSRV, but the 1.85-rejected pattern. Prefer `expose_secret() == &arr`.

29. **`README.md:75-93` (workspace layout)** — lists `secure-gate-core/fuzz/` but not `secure-gate-compat/fuzz/`.

30. **`Cargo.toml:1-4`** — `exclude = ["secure-gate-core/fuzz"]` but not `secure-gate-compat/fuzz`. Both nested fuzz crates have `[workspace]`. Exclude both so a missing `[workspace]` cannot drag libfuzzer into the MSRV `--all-targets` job.

31. **`secure-gate-compat/SECURITY.md:5`** — “Last updated: March 2026 (for v0.9.0)”. This cycle already rewrote the Tier 3 `into_inner` text. Stamp it 2026-09 / rc.9.

32. **PR body vs `f2ef387`** — description still says nightly `redundant-explicit-links` was left alone and rustdoc is stable-only. HEAD added the nightly step and dropped those targets. Update the PR description (not a code bug).

33. **Optional, published crate only** — blocking rustdoc for `secure-gate` is `--no-deps` so CI never checks the configuration docs.rs actually emits (deps present). Keep `--no-deps` on compat (load-bearing). Consider a second `secure-gate` step *with* deps.

---

**Out of scope / not a delta:** versions are consistent at `0.9.0-rc.9`; MSRV is `1.85`; `[Unreleased]` sections are empty placeholders; the six `secure_gate::compat::` paths in `MIGRATING_FROM_SECRECY.md` are gone; `thiserror` is absent from current manifests; `publish = false` does refuse `cargo publish -p secure-gate-compat`.
