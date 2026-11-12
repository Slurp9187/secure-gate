# CI coverage for `release/0.8`, and the cache-poisoning alerts it produces

Status: accepted
Issue: #169
Alerts: code-scanning #9, #11, #12, #13 (`actions/cache-poisoning/poisonable-step`)

## The constraint

GitHub raises `schedule` events **only from the default branch**. A `schedule:`
block committed to `release/0.8` never fires. This is not a configuration
mistake that can be corrected on the 0.8 branch; it is how the event source
works.

So the 0.8 branch cannot schedule its own weekly audit, DSE check, or Miri run.
Before #169 it therefore had none: `cargo audit` never ran against its
dependency tree, and the zeroization and UB guards never ran against its code.

## The shape that fixes it

`.github/workflows/weekly.yml` runs on the cron and on manual dispatch only, and checks out
each branch in turn:

```yaml
strategy:
  matrix:
    ref: [main, "release/0.8"]
steps:
  - uses: actions/checkout@v7
    with:
      ref: ${{ matrix.ref }}
```

It runs `cargo audit` directly, and calls the reusable `dse.yml` and `miri.yml` with that
`ref`, so the weekly runs execute the same steps as the per-commit runs in `ci.yml` and
`miri.yml`. `fuzz-nightly.yml` uses the same matrix for nightly fuzzing.

The workflow runs in the default branch's context (that is where the event was raised) and
checks out the other ref to test it. There is no other way to reach `release/0.8` on a timer.

Before rc.18 each of `audit.yml`, `dse-check.yml` and `fuzz-miri.yml` carried this as a
second job beside its push/PR job, split by `if:` on the event, with a `guard` job to fail
the run if a new trigger left both skipped. Moving the scheduled half into its own workflow
removed the splits, the guards, and the skipped placeholder checks they put on every PR.

## Why CodeQL flags it

`actions/cache-poisoning/poisonable-step` reports:

> Potential cache poisoning in the context of the default branch due to
> privilege checkout of untrusted code from `matrix.ref`.

The flagged locations are the **execution** steps, not cache steps. The table gives the
locations as first reported, in the pre-rc.18 files; the same steps now live in
`weekly.yml`, `dse.yml` and `miri.yml`, so the alerts reappear at those locations and need
the same dismissal:

| Alert | Location | Flagged step |
|-------|----------|--------------|
| #9  | `audit.yml:65`      | `run: cargo audit` |
| #11 | `fuzz-miri.yml:116` | `run: cargo miri setup` |
| #12 | `dse-check.yml:110` | `run: cargo ... test --test asm_dse_check` |
| #13 | `fuzz-miri.yml:122` | `run: cargo miri test ...` |

This matters, and was initially got wrong: the cross-ref jobs were meant to carry **no
dependency cache**, and removing their cache steps did **not** clear the alerts. (They also
did not remove the cache: `actions-rust-lang/setup-rust-toolchain` runs `Swatinem/rust-cache`
itself unless given `cache: false`, so until rc.18 those jobs restored and saved the cache
anyway. The cross-ref calls now pass `cache: false` to the action.) The rule keys on running another ref's code under
default-branch scope at all, because that code could reach the Actions cache
through any tooling it invokes. There is no cache action left to delete.

## Why it is accepted rather than fixed

The rule's premise is *untrusted code*. Here it is not:

- `matrix.ref` is a hardcoded literal — `[main, "release/0.8"]`. It is not
  derived from any event payload, so it is not attacker-influenceable.
- `release/0.8` is a branch of this repository, and is branch-protected.
- The repository has **one** collaborator with push access and **zero** forks.
  Exploiting this requires an actor who can write to `release/0.8` but not to
  `main`. That set is empty; anyone able to poison the 0.8 branch can push to
  the default branch directly and skip the cache entirely.
- All three workflows declare `permissions: contents: read`.

## Alternatives considered

| Option | Why not |
|--------|---------|
| Drop the cross-ref jobs | Returns `release/0.8` to zero scheduled coverage — reintroduces #169 on a branch shipping security-sensitive code. |
| Put `schedule:` on `release/0.8` | Structurally impossible; scheduled events do not fire from non-default branches. |
| Separate workflow with an isolated cache scope | Actions cache scoping falls back to the default branch by design; there is no isolation boundary to place here. |
| Remove the cache steps | Already done, and it did not clear the alerts — the flagged steps are the cargo invocations themselves. |

Dismissed as **won't fix** rather than false positive: the pattern is real and
correctly identified, and the risk is accepted on the threat model above, not
disputed. If the repository ever gains contributors who can write to the 0.8
branch without default-branch access, this decision must be revisited.

## CodeQL on `release/0.8`

Default setup analyses only the default branch and pull requests into it, so `release/0.8`
had no CodeQL analyses at all. `.github/workflows/codeql.yml` is the advanced setup that
replaces it: `push` and `pull_request` on both `main` and `release/0.8`, plus a weekly cron
(which, like every cron, fires only on `main`). It must exist on both branches.

It is active: default setup is off and the repository variable `CODEQL_ADVANCED` is `true`.
The job keeps the `vars.CODEQL_ADVANCED == 'true'` gate so that the file is inert wherever
default setup is still on, since GitHub rejects SARIF from an advanced configuration then.

To check that `release/0.8` is being analysed:

```bash
gh api --paginate 'repos/Slurp9187/secure-gate/code-scanning/analyses?per_page=100' \
  --jq '.[].ref' | sort | uniq -c | sort -rn
```

A nonzero `refs/heads/release/0.8` row is success.
