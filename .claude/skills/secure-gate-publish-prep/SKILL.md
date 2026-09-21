---
name: secure-gate-publish-prep
description: secure-gate's release facts — the per-line toolchain split between main and release/0.8, what a bump touches here, what the package must carry, and the traps that have cost time. Use when cutting or publishing 0.9.x from main or 0.8.x from release/0.8, or when a tag needs moving.
---

# Publish prep — secure-gate

The order and the mechanics — `is it worth releasing at all?`, verify, cut, dry run, **tag
last**, hand over — are in the global `publish-prep` skill, along with tag pushing and the
prepare-only rule. What the changelog may *claim* is in
`secure-gate-changelog-protocol`. **This file records only what is true of this repository.**

**You prepare up to `cargo publish --dry-run`. The maintainer publishes.**

## Verify, and the toolchain differs per line

This is the largest local fact. `RUSTFLAGS="-D warnings"` on everything.

| Gate | `main` | `release/0.8` |
|---|---|---|
| `fmt --check` | stable | **`+1.70`** — its rustfmt wraps differently |
| `check -p secure-gate --locked --features=full` | stable | **`+1.70`** |
| `test --features full` and `--all-features` | stable | **`+1.70`** |
| `clippy --all-features --all-targets` | stable | **stable** — 1.70 has no `unexpected_cfgs` and passes *falsely* |
| `doc --no-deps` | `--all-features` | **`--features=full`** |
| compile-fail snapshots | 1.85 | **`+1.70`**, trybuild `=1.0.81` |

Two rows are counterintuitive and both are deliberate. **Clippy runs on stable even for 0.8**,
because an older compiler does not know a lint exists and therefore passes for the wrong
reason. And **`cargo doc` is its own gate** — `-D warnings` promotes broken intra-doc links to
errors and nothing else reaches them. On 0.8 it runs `--features=full`, which does **not**
enable `std` — so any doc comment linking to a `std` item resolves on `main`'s `--all-features`
build and fails here, which is the whole reason that job catches things the others do not.

*(The previous revision pointed at a `backport-08-gotchas` document for this. No such file
exists on either branch — it was a dangling reference, so the fact is stated inline instead.)*

## The cut

Replace `Unreleased` with the ISO date in the top heading. **That is the entire cut** — no
publication note, for the reasons in the changelog skill.

```sh
grep -m1 '^version' Cargo.toml          # manifest
grep -m1 '^## \[' CHANGELOG.md          # heading — must match
git tag -l "v$VER"                      # absent before the cut commit
grep -m1 '^version' Cargo.lock          # 0.8 must stay `version = 3`
```

Or run the global checker in `--mode release` on the tag build.

**On `release/0.8`, hand-edit the `Cargo.lock` root-package line** if the version moved. Never
run `cargo update` there — the toolchain is pinned to 1.70 and a newer cargo reformats the file
or disturbs the MSRV-driven pins.

## What a bump touches here

Every concrete version in `README.md` equals the manifest, **changed in the same commit** — the
docs.rs badge on 0.8, the exact-pin example, any sort-order example. There is no staged
"moves at publish time" rule; it existed, it was confusing, and it is gone. The cost is
explicit: between the bump and the upload those name a version crates.io does not have yet.
Minutes on a line publishing promptly; as long as the candidate stays open on one that is not.

**Never move:**

- The **three install snippets** — they use the tracking form `"0.8.0-rc"` / `"0.9.0-rc"` and
  carry no version.
- Anything recording *when* something happened: which tag last carried `secure-gate-compat`,
  the `0.1.0–0.7.0-rc.14` yank line, "changed in rc.13" statements in `SECURITY.md`.

## Tags, local facts only

`git push --follow-tags origin <branch>`; the mechanics are global.

- **Never `--tags`.** This repo carries **14 lightweight `v0.7.0-rc.*` tags** from the yanked
  line; `--tags` would publish every one.
- **Every current tag on both lines is published**, which makes them effectively immutable —
  re-cutting one would move a ref that crates.io artifacts already correspond to. Treat a
  published tag as fixed and open the next version instead.

## Dry run, and what the package must carry

```sh
cargo +1.70 publish --locked --dry-run     # +1.70 on release/0.8, stable on main
```

```sh
cargo package --locked --list | grep -E '^(SECURITY|README|CHANGELOG)'
tar -xzOf target/package/secure-gate-$VER.crate secure-gate-$VER/README.md | sed -n '3p'
```

**`SECURITY.md`, `README.md` and `CHANGELOG.md` ship** — they are in `include`. `tests/`, the
example, `tools/` and the receipts do **not**. That matters more here than in most crates: this
crate's security guidance *is* part of what it delivers, so a consumer who cannot read
`SECURITY.md` from the tarball has a materially different package.

## Windows traps that have cost time here

- **`/tmp` is invisible to Windows python.** A heredoc written to `/tmp` then read by `python`
  fails with a path that does not exist. Use the session scratchpad and a Windows-style path.
- **`export MSYS_NO_PATHCONV=1`** before any `git show <rev>:<path>` — MSYS rewrites the colon.
- **`gh api` truncates at 30** without `--paginate`.
- **A script that aborts must not leave the commit running.** A failed assertion followed by an
  unchained `git commit` has shipped an incomplete change here. Chain them.

## What did not transfer

- **The ordering rules and their reasoning** — tag last because it is the only expensive step to
  redo, the dry run needing no tag, `is it worth releasing at all?` and its doc-stripped code
  delta. All general, all now in the global skill. The 0.8.0-rc.14 release that cut its tag four
  times is the evidence behind the global rule rather than a fact about this repo.
- **Tag mechanics** — annotated, `--follow-tags` versus `--tags`, the no-op-reported-as-success,
  `^{}` dereferencing to check what landed. Kept here only where the fact is local: the 14
  lightweight tags, and that every current tag is published.
- **The registry existence query.** It lives in `secure-gate-changelog-protocol`, because what
  it settles is a claim the changelog makes.
