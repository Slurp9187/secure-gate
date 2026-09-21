---
name: secure-gate-changelog-protocol
description: secure-gate's changelog facts across its two release lines — the version of record per line, the publication axis that is the one that actually breaks here, and the measurements behind having no CI gate for it. Use when writing or reviewing changelog entries, bumping the version, cutting a release, or before asserting in prose that a version is or is not published.
---

# Changelog protocol — secure-gate

The protocol itself — the invariants, the heading format, entry dating, the release flow, what
a bump touches — is in the global `changelog-protocol` skill, along with its checker. Tag
mechanics and release ordering are in the global `publish-prep`. **This file records only what
is true of this repository.**

## The failure mode here is a sentence, not a heading

Worth stating first, because it decides where attention goes.

**Measured over 400 commits across both branches**, the version in the top heading has *never*
diverged from the manifest, and no top section has ever been dated without its tag. What did go
wrong, **twice**, was a blockquote reading *"Tagged, **not yet published to crates.io**"* about
versions that were live on crates.io — on both branches simultaneously.

That survived a dedicated link audit (#210 / #211) which checked every anchor, path and URL on
both branches, **because reading the file cannot catch it. It needs a query.**

So: **write no publication note at all.** The heading already carries the state in a slot that
cannot go stale. A note of the form `> Published to crates.io on the v0.9.0-rc.9 tag.` is
accurate and harmless but not worth writing; `> not yet published` is true for days and then
rots. Existing notes in historical sections are left alone.

**Never write a publication claim from memory or inference.** A tag existing is not evidence,
and neither is a changelog section that said so last month.

## Publication is a separate axis from tagging

The repo has durable instances of the two disagreeing:

| state | example |
|---|---|
| tagged **and** published | `v0.9.0-rc.9` — the normal case |
| published, **never tagged** | `0.8.0-rc.7`, and everything before `0.7.0` |
| tagged, not yet published | transient only — minutes, between cutting and uploading |
| neither | the version currently in flight |

The third row has no durable instance worth citing, which is exactly why a note saying *"tagged,
not yet published"* is almost always already false by the time anyone reads it.

**The query**, and the only thing that settles it — the sparse index lists only published
versions, so presence *is* publication:

```powershell
$idx = (Invoke-WebRequest -Uri "https://index.crates.io/se/cu/secure-gate" -UseBasicParsing).Content
$idx -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $o = $_ | ConvertFrom-Json
  [pscustomobject]@{ vers = $o.vers; yanked = $o.yanked } } |
  Sort-Object { [version]($_.vers -replace '-.*$','') }, vers | Select-Object -Last 8
```

```sh
curl -s https://index.crates.io/se/cu/secure-gate | jq -r 'select(.yanked==false) | .vers' | tail -8
```

## Two lines, two changelogs, one crate

`main` (0.9.x, edition 2024, MSRV 1.85) and `release/0.8` (0.8.x, edition 2021, MSRV 1.70) are
independently versioned and tagged, and **each branch's `CHANGELOG.md` describes only its own
line.** One changelog per branch, at the root.

This is the exception to the global skill's *one changelog at the root* preference: the two
lines have genuinely independent versioning and distribution, which is the test that section
names.

Entries legitimately differ between the two, and **a diff between them is not a defect to be
reconciled.** Dependency and toolchain bumps are **never** ported to `release/0.8` — see the
branch table in `README.md` and `docs/audits/pr-182-backport-ledger.md`. When a fix lands on
`main` and cannot come here, say so in the 0.8 section rather than leaving a reader to wonder
whether it was forgotten.

`Cargo.lock` on `release/0.8` must stay `version = 3`.

## Historical oddities that are not errors

Scoping the invariants to the top section is the global rule; these are what it protects:

- `[0.8.0-rc.7]` is dated and published, but **its tag is gone.**
- The pre-`0.7.0` releases predate both the changelog and the tag scheme.
- 14 lightweight `v0.7.0-rc.*` tags from the yanked line are still present locally.

None of these is actionable. A checker that failed on them is a checker someone disables.

## Why there is no CI gate for this

Recorded with the numbers so the decision can be re-examined rather than re-argued.
**Measured 2026-09-14:**

| invariant | result |
|---|---|
| top heading matches manifest | **0 divergences** across 200 commits on `main` and 200 on `release/0.8` |
| dated iff tagged | **0** top sections ever dated without a tag. The single hit across all 24 dated sections is `[0.8.0-rc.7]` — a legitimate state a top-section-only check ignores anyway |
| publication claims | **2 real defects**, on both branches simultaneously. The only one of the three that has ever actually broken |

A gate on the first two would have caught **nothing in 400 commits**, and would have reported a
clean pass on both branches *while both carried a false publication claim*.

The publication check is the one worth running — but **a pull request cannot make that claim
wrong, only publishing can**, so it belongs on a release checklist rather than a merge gate,
where it would also make merges depend on crates.io being reachable.

The case rests on those measurements alone, so state what it does *not* rest on: `.gitignore`
now commits `.claude/skills/`, so a checker placed there would be visible to a workflow. The
mechanical obstacle was removed deliberately; the decision stands on the hit rate.

One real cost remains. The branches carry **separate CI files** — `ci.yml` (`branches: [main]`)
and `ci-0.8.yml` — and per the backport ledger, CI changes must be **re-derived** for 0.8, not
copied. Every check is built and maintained twice, on two branches meant to diverge.

**Reconsider if** the publication claim rots twice more, or if the lines ever stop being bumped
by hand.

## Heading format

This repo already uses the canonical `## [0.9.0-rc.13] - Unreleased` form — brackets, ASCII
hyphen, capital `Unreleased`. The global checker passes clean here. No migration needed.

## Windows notes

- `git show <rev>:<path>` — MSYS rewrites the colon. `$env:MSYS_NO_PATHCONV=1` first.
- `gh api` truncates at 30 results without `--paginate`.

## What did not transfer

- **The global skill's tag mechanics.** Annotated tags, `--follow-tags` versus `--tags`, the
  no-op-reported-as-success — all moved to `publish-prep`, where ordering lives. This file kept
  only the fact that a tag is the release marker.
- **Its automated-checker guidance.** The checker exists and passes here, but this repo runs no
  CI gate for it, on the measured grounds above. That is the *deliberately none* branch of the
  global skill's enforcement rule, with the numbers attached.
- **Its one-changelog-at-the-root preference.** Two release lines with independent versioning
  and distribution is the case that section explicitly carves out.
