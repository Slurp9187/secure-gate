---
name: secure-gate-changelog-protocol
description: Keep secure-gate's CHANGELOG honest across its two release lines by making every claim in it verifiable. Use when writing or reviewing changelog entries, bumping the version, cutting or tagging a release, publishing to crates.io, or when a section's version, date, or publication note looks out of step with the manifest, the tags, or the index. Also use before asserting in prose that a version is or is not published.
---

# Changelog protocol

A changelog is a set of claims about what shipped and when. This protocol keeps
each claim checkable.

secure-gate's actual failure mode is **not** a malformed heading. Measured over
400 commits across both branches, the version in the top heading has *never*
diverged from the manifest, and no top section has ever been dated without its
tag. What did go wrong, twice, was a sentence: both branches carried a
blockquote reading *"Tagged, **not yet published to crates.io**"* about versions
that were live on crates.io. That survived a dedicated link audit (#210 / #211)
which checked every anchor, path and URL on both branches — because reading the
file cannot catch it. It needs a query.

So the invariants below are ordered by how often they actually break here, not
by how easy they are to check.

## The four invariants

### 1. Publication is a separate axis from tagging

This is the one that breaks. Tagging and publishing are independent, and the
repo has durable instances of them disagreeing:

| state | example |
|---|---|
| tagged **and** published | `v0.9.0-rc.9` — the normal case |
| published, **never tagged** | `0.8.0-rc.7`, and everything before `0.7.0` |
| tagged, not yet published | transient only — step 3 to step 4 of the flow below |
| neither | the version currently in flight |

The third row has no durable instance worth citing: it is the window between
cutting a tag and publishing it. Treat it as a state you pass through in
minutes, not one to describe in a changelog — which is why a note saying
*"tagged, not yet published"* is almost always already false by the time anyone
reads it.

A tag therefore proves nothing about crates.io, and the index proves nothing
about tags. **Never write a publication claim from memory or inference** — a tag
existing is not evidence, and neither is a changelog section that said so last
month.

Prefer notes with no shelf life. `> Published to crates.io on the v0.9.0-rc.9
tag.` stays true forever; `> not yet published` is true for days and then rots
silently, because nothing re-reads it.

### 2. The top heading's version matches the manifest

Whatever `Cargo.toml` says, the newest section is headed with that exact string.

### 3. A heading carries a date if and only if its tag exists

```
## [0.9.0-rc.10] - Unreleased      while the work is in flight
## [0.9.0-rc.10] - 2026-09-14      the moment v0.9.0-rc.10 is cut
```

One separator, two possible values. The date **is** the release marker — not
decoration, not the date the work happened.

**This applies to the top section only.** Historical sections accumulate
legitimate oddities: `[0.8.0-rc.7]` is dated and published but its tag is gone,
and the pre-`0.7.0` releases predate both the changelog and the tag scheme.
Those are not errors and there is nothing to do about them. The top section is
where the mistake actually happens, because it is the one being edited.

### 4. Two lines, two changelogs, one crate

`main` (0.9.x, edition 2024, MSRV 1.85) and `release/0.8` (0.8.x, edition 2021,
MSRV 1.70) are independently versioned and tagged, and each branch's
`CHANGELOG.md` describes **only its own line**. There is exactly one changelog
per branch, at the root.

Entries legitimately differ between the two, and a diff between them is not a
defect to be reconciled. Dependency and toolchain bumps are **never** ported to
`release/0.8` — see the branch table in `README.md` and
`docs/audits/pr-182-backport-ledger.md`. When a fix lands on `main` and cannot
come here, say so in the 0.8 section rather than leaving a reader to wonder
whether it was forgotten.

## No standing bare `[Unreleased]`

The versioned-but-undated section *is* the unreleased one. Keeping a bare
`## [Unreleased]` as well leaves a reader unable to tell which section describes
the code they have — the exact ambiguity this protocol removes.

secure-gate always knows its next version when a line opens, so name it:
`## [0.9.0-rc.10] - Unreleased`. This also matches the `## [VERSION] - DATE`
shape every other section uses, with the date slot filled by `Unreleased` until
the tag is cut.

## Do not date individual entries

Git already records when each change landed, precisely. A hand-typed date is a
lossy copy that costs a decision per entry and answers a question no reader
asks — they ask *"what changed between the version I have and the one I am
considering?"*

**Except** when the date is part of the claim. The test:

> Does the reader need the date to know how stale an *observation* is?

```markdown
<!-- KEEP — the date bounds the evidence -->
- Reproduced against `base32ct` 0.2.2 on 2026-09-09; 0.3.1 is clean.
- No RUSTSEC advisory exists as of 2026-09-13, so `cargo audit` does not flag it.

<!-- DROP — git already knows -->
- Raised the base32ct floor to 0.3.1 (2026-09-13).
```

## What a version bump touches

From the precedent set by 801cc7b (`main`) and d354287 (`release/0.8`), which
enumerate this explicitly. A bump moves **version identity** and must not
falsify **historical statements**.

**Move:**

- the `version` in `Cargo.toml`
- `Cargo.lock` (on `release/0.8`, hand-edit the one root-package line — the
  toolchain is pinned to 1.70 and a newer cargo will reformat the file or
  disturb the MSRV-driven pins)
- the three install snippets in `README.md`

**Leave alone:**

- Anything recording *when* something happened: "backported to the 0.8 line in
  0.8.0-rc.11", "released as 0.8.0-rc.11", the `v0.8.0-rc.11` /
  `v0.9.0-rc.8` references naming the last tag that carried
  `secure-gate-compat`.
- On `release/0.8`, the versioned docs.rs badge and `Cargo.toml`'s
  `documentation` field. 0153d60 set these to *"the version this README ships
  with"* specifically to fix a 404 against an unpublished version; pointing them
  at an unpublished version again recreates that defect. They move at **publish**
  time, not at bump time. (`main` uses unversioned docs.rs URLs and has neither.)

## The release flow

1. **Open the line.** Bump the manifest and add `## [<next>] - Unreleased` at
   the top, in the same commit. Do this on the first commit after a tag, so no
   work ever lands on a published version.
2. **Accumulate.** Entries under that heading, grouped `### Added` /
   `### Changed` / `### Fixed` / `### Removed` / `### Security`. No dates unless
   the date is evidence.
3. **Cut.** Replace `Unreleased` with the ISO date, commit, tag from that commit.
4. **Publish**, then update the section's note to say so — and on
   `release/0.8`, move the docs.rs badge and `documentation` field now.
5. **Repeat.** Never leave a standing empty section.

An opened section with **no entries** is correct and expected at step 1 — it
means the line is open and nothing has landed. Say that in its note so the
emptiness reads as deliberate.

## Checks to run when cutting a release

There is deliberately no script and no CI for this; see below. Two commands
cover it.

**Invariants 2 and 3** — manifest, top heading, and tag, in one look:

```powershell
$v = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$h = (Select-String -Path CHANGELOG.md -Pattern '^## \[([^\]]+)\]\s*-\s*(.+)$' | Select-Object -First 1).Matches[0]
"manifest : $v"
"heading  : [$($h.Groups[1].Value)] - $($h.Groups[2].Value)"
"tag v$v  : $(if (git tag -l "v$v") { 'exists' } else { 'absent' })"
```

Heading version must equal the manifest. The marker must be `Unreleased` exactly
when the tag is absent, and an ISO date exactly when it is present.

**Invariant 1** — what crates.io actually has:

```powershell
$idx = (Invoke-WebRequest -Uri "https://index.crates.io/se/cu/secure-gate" -UseBasicParsing).Content
$idx -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $o = $_ | ConvertFrom-Json
  [pscustomobject]@{ vers = $o.vers; yanked = $o.yanked } } |
  Sort-Object { [version]($_.vers -replace '-.*$','') }, vers | Select-Object -Last 8
```

The sparse index lists only published versions, so presence *is* publication.
Run this before writing or trusting any note about publication status.

Bash equivalent, for CI or a non-Windows checkout:

```sh
curl -s https://index.crates.io/se/cu/secure-gate | jq -r 'select(.yanked==false) | .vers' | tail -8
```

## Why there is no CI for this

Recorded with the numbers so the decision can be re-examined rather than
re-argued. Measured 2026-09-14:

- **Invariant 2** — 0 divergences between manifest and top heading across 200
  commits on `main` and 200 on `release/0.8`.
- **Invariant 3** — 0 top sections ever dated without a tag. The single hit
  across all 24 dated sections is `[0.8.0-rc.7]`, published with its tag since
  deleted: a legitimate state, and one a top-section-only checker ignores anyway.
- **Invariant 1** — 2 real defects, on both branches simultaneously, and the
  only one of the four that has ever actually broken.

A gate on invariants 2 and 3 would have caught nothing in 400 commits, and would
have reported a clean pass on both branches *while both carried a false
publication claim*. The publication check is the one worth running — but a pull
request cannot make that claim wrong, only publishing can, so it belongs on a
release checklist rather than in a merge gate, where it would also make merges
depend on crates.io being reachable.

The case rests on those measurements alone, so state what it does *not* rest on:
`.gitignore` now commits `.claude/skills/` (everything else under `.claude/` is
local), which means a checker placed here would be visible to a workflow. The
mechanical obstacle was removed deliberately; the decision stands on the hit
rate, not on the plumbing.

One real cost remains. The branches carry **separate CI files** — `ci.yml`
(`branches: [main]`) and `ci-0.8.yml` — and per the backport ledger, CI changes
must be *re-derived* for 0.8, not copied. Every check is built and maintained
twice, on two branches that are meant to diverge.

Reconsider if the publication claim rots twice more, or if the lines ever stop
being bumped by hand.

## Windows notes

- `git show <rev>:<path>` — MSYS rewrites the colon into a semicolon. Run
  `$env:MSYS_NO_PATHCONV=1` first, or the command fails with a path that does
  not exist.
- `gh api` truncates at 30 results without `--paginate`.

## Pushing tags

`gh` does not push tags. Use git, and make the tag **annotated**:

```sh
git tag -a v0.9.0-rc.10 -m "v0.9.0-rc.10"
git push --follow-tags
```

`--follow-tags` pushes the branch **and** annotated tags reachable from those
commits that are missing on the remote. It does not push lightweight tags, and
it does not push unrelated local tags.

**It will not move a tag that already exists** — it reports `Everything
up-to-date` while the remote keeps the old commit. Moving a tag is always
`git push -f origin v0.9.0-rc.10`, by name. A no-op reported as success is the
worst shape a failure can take, so check rather than assume.

Every current tag on both lines is published, which makes them effectively
immutable: re-cutting one would move a ref that crates.io artifacts already
correspond to. Treat a published tag as fixed and open the next version instead.

Avoid `git push --tags` — it publishes *every* local tag, including the
corrupted `v0.7.0-rc.*` markers still present locally.
