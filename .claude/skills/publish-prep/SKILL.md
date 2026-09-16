---
name: publish-prep
description: Prepare a secure-gate release for crates.io on either line — verify, cut the changelog, tag, and dry-run — in an order that does not need redoing. Use when cutting or publishing 0.9.x from main or 0.8.x from release/0.8, when a tag needs moving, or when deciding whether unreleased work is worth a release at all. Covers the per-line toolchain split, the tag mechanics, and the Windows traps that cost time here.
---

# Publish prep

The mechanics of getting a release out. `changelog-protocol` governs what the
changelog may *claim*; this governs the order you do things in, which is where
the time actually goes.

**You prepare up to `cargo publish --dry-run`. The maintainer publishes.** Never
run the real upload.

## Tag last. This is the whole lesson.

Every other step is cheap to redo. A tag is not: moving one is
`git tag -f` + `git push -f` + re-running the dry run, because the packaged tree
changed. On 0.8.0-rc.14 the tag was cut four times — once each for a badge edit,
a maintainer edit landing in parallel, and a comment change.

```
verify → cut the changelog → dry-run → confirm → tag → hand over
```

The dry run does **not** need a tag: it packages the working tree. So tagging
after it means nothing can happen between the tag and the upload except the
upload. Before tagging, ask whether the maintainer has edits coming — parallel
edits are what invalidated two of those four tags.

## Is it worth releasing at all?

Ask before doing any of the above. Measure the delta in **code**, not lines:

```sh
git diff <last-published-tag>..origin/<branch> -- src/ \
  | grep -E '^[+-]' | grep -vE '^[+-]{3}' \
  | grep -vE '^[+-]\s*(///|//!|//)' | grep -vE '^[+-]\s*$'
```

This crate is ~58% doc comments, so a large diffstat routinely means nothing
shipped. A release whose delta is documentation plus a breaking change is a bad
trade for consumers who just pinned the previous one: they absorb the break and
gain nothing. Say so rather than preparing it.

The argument *for* releasing is a defect fixed in unreleased code that is live
in published code. That is what made 0.8.0-rc.14 worth cutting: the newest
published release on the line still shipped the zero-capacity `new_with(f)`.

## Verify first, under the branch's own CI conditions

`RUSTFLAGS="-D warnings"` on everything, and mind the toolchain split.

| Gate | `main` | `release/0.8` |
|---|---|---|
| `fmt --check` | stable | **`+1.70`** — its rustfmt wraps differently |
| `check -p secure-gate --locked --features=full` | stable | **`+1.70`** |
| `test --features full` and `--all-features` | stable | **`+1.70`** |
| `clippy --all-features --all-targets` | stable | **stable** — 1.70 has no `unexpected_cfgs` and passes falsely |
| `doc --no-deps` | `--all-features` | **`--features=full`** |
| compile-fail snapshots | 1.85 | **`+1.70`**, trybuild `=1.0.81` |

`cargo doc` is its own gate: `-D warnings` promotes broken intra-doc links to
errors and nothing else reaches them. On 0.8 it runs `--features=full`, which
does **not** enable `std` — see `backport-08-gotchas` for why that bites.

## The cut

Replace `Unreleased` with the ISO date in the top heading. That is the entire
cut. Do **not** add a publication note: the date is the release marker, and a
prose claim about crates.io is the only thing in the file with a shelf life —
it has rotted twice here.

Then confirm the invariants in one look:

```sh
grep -m1 '^version' Cargo.toml          # manifest
grep -m1 '^## \[' CHANGELOG.md          # heading — must match
git tag -l "v$VER"                      # absent before the cut commit
grep -m1 '^version' Cargo.lock          # 0.8 must stay `version = 3`
```

On `release/0.8`, hand-edit the `Cargo.lock` root-package line if the version
moved. Never run `cargo update` there — the toolchain is pinned to 1.70 and a
newer cargo reformats the file or disturbs the MSRV-driven pins.

### Versions in README match `Cargo.toml`, always

Every concrete version in `README.md` — the docs.rs badge, the exact-pin
example, any sort-order example — equals the manifest, changed in the same
commit. There is no staged "moves at publish time" rule; it existed, it was
confusing, and it is gone.

The cost is explicit: between the bump and the upload those name a version
crates.io does not have. Minutes on a line publishing promptly; as long as the
candidate stays open on one that is not.

**Never move:** the three install snippets (they use the tracking form
`"0.8.0-rc"` / `"0.9.0-rc"` and carry no version), and anything recording *when*
something happened — which tag last carried `secure-gate-compat`, the
`0.1.0–0.7.0-rc.14` yank line, "changed in rc.13" statements in SECURITY.md.

## Tagging

Annotated, always. Push the branch and the tag together:

```sh
git tag -a v0.8.0-rc.15 -m "v0.8.0-rc.15"
git push --follow-tags origin release/0.8
```

**`--follow-tags`, never `--tags`.** It pushes annotated tags reachable from the
pushed commits and ignores lightweight ones. This repo carries 14 lightweight
`v0.7.0-rc.*` tags from the yanked line; `--tags` would publish them.

**Neither flag moves an existing tag.** `--follow-tags` reports
`Everything up-to-date` while the remote keeps the old commit — a no-op reported
as success. To move one:

```sh
git push -f origin v0.8.0-rc.14
```

Tags move freely before publication. A published tag is immutable: crates.io
artifacts correspond to it. If a published tag is wrong, open the next version.

Verify what actually landed — annotated tags show the *tag object* SHA, so
dereference:

```sh
git ls-remote --tags origin 'v0.8.0-rc.14^{}'   # the commit
git rev-parse origin/release/0.8                 # must match
```

## Dry run

```sh
cargo +1.70 publish --locked --dry-run     # +1.70 on release/0.8, stable on main
```

Then check the package actually carries what you think:

```sh
cargo package --locked --list | grep -E '^(SECURITY|README|CHANGELOG)'
tar -xzOf target/package/secure-gate-$VER.crate secure-gate-$VER/README.md | sed -n '3p'
```

`SECURITY.md` and `README.md` ship (they are in `include`); `tests/` does not.

## After the maintainer publishes

Confirm against the sparse index. **Never infer publication from a tag, a
changelog sentence, or memory:**

```sh
curl -s https://index.crates.io/se/cu/secure-gate | jq -r 'select(.yanked==false)|.vers' | tail -5
```

Then **nothing else**. No publication note, no badge move — the badge already
matches the manifest, and now resolves. That emptiness is the point: the old
flow put three edits here and they were missed twice.

**Do not open the next line speculatively.** Leaving the manifest equal to the
published version is the correct resting state. Open the next version in the
same commit as the first real work that arrives.

## Windows traps that have cost time here

- **`/tmp` is invisible to Windows python.** A heredoc written to `/tmp` then
  read by `python` fails with a path that does not exist. Use the session
  scratchpad and pass a Windows-style path.
- **`export MSYS_NO_PATHCONV=1`** before any `git show <rev>:<path>` — MSYS
  rewrites the colon.
- **`gh api` truncates at 30** without `--paginate`.
- **A script that aborts must not leave the commit running.** A failed
  assertion followed by an unchained `git commit` has shipped an incomplete
  change here. Chain them.
