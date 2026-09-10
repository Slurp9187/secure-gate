# CI coverage for `release/0.8`, and the cache-poisoning alerts it produces

Status: accepted
Issue: #169
Alerts: code-scanning #9, #11, #12, #13 (`actions/cache-poisoning/poisonable-step`)

## The constraint

GitHub raises `schedule` events **only from the default branch**. A `schedule:`
block committed to `release/0.8` never fires. This is not a configuration
mistake that can be corrected on the LTS branch; it is how the event source
works.

So the LTS branch cannot schedule its own weekly audit, DSE check, or Miri run.
Before #169 it therefore had none: `cargo audit` never ran against its
dependency tree, and the zeroization and UB guards never ran against its code.

## The shape that fixes it

Each of `audit.yml`, `dse-check.yml` and `fuzz-miri.yml` carries a second job,
gated to `schedule` / `workflow_dispatch`, with

```yaml
strategy:
  matrix:
    ref: [main, "release/0.8"]
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ matrix.ref }}
```

The workflow runs in the default branch's context (that is where the event was
raised) and checks out the other ref to test it. There is no other way to reach
`release/0.8` on a timer.

## Why CodeQL flags it

`actions/cache-poisoning/poisonable-step` reports:

> Potential cache poisoning in the context of the default branch due to
> privilege checkout of untrusted code from `matrix.ref`.

The flagged locations are the **execution** steps, not cache steps:

| Alert | Location | Flagged step |
|-------|----------|--------------|
| #9  | `audit.yml:65`      | `run: cargo audit` |
| #11 | `fuzz-miri.yml:116` | `run: cargo miri setup` |
| #12 | `dse-check.yml:110` | `run: cargo ... test --test asm_dse_check` |
| #13 | `fuzz-miri.yml:122` | `run: cargo miri test ...` |

This matters, and was initially got wrong: the cross-ref jobs already carry **no
dependency cache**, deliberately, and removing those cache steps did **not**
clear the alerts. The rule keys on running another ref's code under
default-branch scope at all, because that code could reach the Actions cache
through any tooling it invokes. There is no cache action left to delete.

## Why it is accepted rather than fixed

The rule's premise is *untrusted code*. Here it is not:

- `matrix.ref` is a hardcoded literal — `[main, "release/0.8"]`. It is not
  derived from any event payload, so it is not attacker-influenceable.
- `release/0.8` is a branch of this repository, and is branch-protected.
- The repository has **one** collaborator with push access and **zero** forks.
  Exploiting this requires an actor who can write to `release/0.8` but not to
  `main`. That set is empty; anyone able to poison the LTS branch can push to
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
disputed. If the repository ever gains contributors who can write to the LTS
branch without default-branch access, this decision must be revisited.

## Known gap: CodeQL does not scan `release/0.8`

Code scanning is on **default setup**, which analyses the default branch and
pull requests targeting it. It has no multi-branch option. As a result:

- `release/0.8` has **zero** CodeQL analyses, against 751 on `main`.
- Pull requests into `release/0.8` receive no CodeQL checks at all. PR #190 —
  changed 191 files across a full repository flatten — was merged without any.

Closing this requires migrating to advanced setup: committing a `codeql.yml`
workflow to both branches and disabling default setup in repository settings.
That is a settings change, not something a pull request can carry.

### Migration, prepared

`.github/workflows/codeql.yml` carries the advanced setup that closes the gap:
`push` and `pull_request` on both `main` and `release/0.8`, plus the same weekly
cron, for both configured languages (`actions`, `rust`).

It ships **inert**. The analyze job is gated on `vars.CODEQL_ADVANCED == 'true'`
because GitHub rejects SARIF from an advanced configuration while default setup
is still enabled — an ungated workflow would fail every push and PR in the
window between merging the file and changing the setting. Activation is:

1. Settings → Code security → Code scanning → CodeQL analysis → turn
   **Default setup** off.
2. Settings → Secrets and variables → Actions → Variables → set
   `CODEQL_ADVANCED` = `true`.

**Do these in order.** Step 2 before step 1 lets the analyze job run while
default setup is still enabled, and GitHub rejects its SARIF upload -- the exact
red state the gate exists to prevent. Step 1 first is safe: the workflow keeps
skipping until the variable is set, so the only cost is a short window with no
scanning.

Both steps are repository-settings changes and cannot be performed by a pull
request.

After activating, `release/0.8` still has no analyses until the workflow actually
runs there. Trigger it from the Actions tab (**Run workflow** -> branch
`release/0.8`) or with `gh workflow run codeql.yml --ref release/0.8`; both need
the `workflow_dispatch:` trigger, which this workflow carries for exactly that
reason. The weekly cron does **not** cover that branch -- scheduled events fire
only from the default branch, so `release/0.8` is reached by push and
pull_request alone.

Success is a nonzero `refs/heads/release/0.8` row in:

```bash
gh api --paginate 'repos/Slurp9187/secure-gate/code-scanning/analyses?per_page=100'   --jq '.[].ref' | sort | uniq -c | sort -rn
```

A 200 from the settings API is not success. Until they are made, `release/0.8` remains unscanned.
