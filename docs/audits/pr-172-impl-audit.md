Reviewed [PR #172](https://github.com/Slurp9187/secure-gate/pull/172) from a separate worktree on `claude/handoff-semantics` (`b1550dc`), then removed that worktree so it does not lock the branch against the in-flight #171 fixes.

**Verdict:** the three code changes are coherent and I would not send them back. I would **not merge as written**. `SECURITY.md` / README / a chunk of the changelog still describe the crate this PR deletes — including a wipe-on-extract guarantee that no longer exists. For a secrets library that is a merge blocker, not copy-editing.

---

## What the impl actually does (and gets right)

The through-line in the PR body matches the code:

1. **Every encoder returns `EncodedSecret`.** `_zeroizing` twins are gone. Macros, `Fixed`/`Dynamic`, and the blankets all agree. `&*encoded` is the `&str` bind path; `.into_inner()` is the named end of protection.
2. **`into_inner()` returns `T`.** Sentinel swap on `Fixed` / `Dynamic` is the same mechanism as before; `dynamic_into_inner_moves_without_copying` pins pointer identity for `Vec<u8>`. Panic-before-swap still leaves the real secret in `Dynamic` for `Drop` to wipe.
3. **`EncodableBytes` is load-bearing.** The trybuild stderr is the proof: `encoded.to_hex()` dies because `str: EncodableBytes` is not satisfied, not because of a missing `AsRef`. That is the right fix for the re-encode footgun.

No `PartialEq` on `EncodedSecret` is a reasonable call. Deleting the 43 tautological encoder-twin tests is fine.

---

## Findings

| Severity | Location | Finding |
|---|---|---|
| **High** | `SECURITY.md`, `README.md` | Threat-model docs still promise `InnerSecret` wipe-on-extract and leaky `to_hex() -> String`. After this PR both claims are false. |
| **High** | `CHANGELOG.md` Unreleased | Documents `into_plain()` / `InnerSecret` as if they shipped; the landed API is `into_inner() -> T`. Also still claims `encoded.to_hex()` compiles, which the trybuild now proves does not. |
| Medium | `CHANGELOG.md` L105–109 | Merge artifact: the 1023-bound bullet is duplicated/garbled (`8191 — eight times` then `8191 — roughly eight times`). |
| Medium | `lib.rs` EncodedSecret rustdoc | Still lists `AsRef<str>` / `AsRef<[u8]>` after those impls were removed. |
| Medium | `encoded_secret.rs` L9–10, L117–123 | Module docs still describe a String/zeroizing split and say re-encode “still compiles.” Opposite of the code. |
| Low | `fixed_newtype.rs` | Same #171 hole: BIP-173 decode is inside `__sg_if_alloc!`, bech32m is not. This PR does not fix it and will conflict with the follow-up branch. |

### 1. SECURITY.md would ship lying

The encoding table is still the old two-flavor model:

```423:428:secure-gate-core/SECURITY.md
Encoding methods ... come in two flavors:
| `to_hex()` ... | `String` ... | No | Public encodings |
| `to_hex_zeroizing()` ... | `EncodedSecret` | Yes | Sensitive encodings |
```

And extraction is still:

> `into_inner` — returns `InnerSecret<T>` (wraps `Zeroizing<T>`); zeroization transfers to caller.

After this PR, `into_inner()` returns a plain `[u8; N]` / `String` / `Vec<T>` that **does not wipe**. That is an intentional, documented-in-rustdoc removal of a guarantee. Leaving the security doc on the old contract is the kind of lie this crate exists to not tell. README’s “owned extraction → `InnerSecret<T>`” and “prefer `*_zeroizing`” lines are the same bug on the front page.

Compat’s `SECURITY.md` still says zeroization transfers to `InnerSecret<T>` too.

### 2. Changelog describes a different PR than the one that would merge

The Unreleased section still has the intermediate `into_plain()` / `InnerSecret::into_plain()` bullet. That type and method are gone. A later bullet still says:

> **This does not close the accidental re-encode.** `encoded.to_hex()` still compiles…

That was true when `AsRef` was stripped and `EncodableBytes` did not exist yet. It is false in `b1550dc`. `encoded_secret_no_reencode.stderr` is the counterexample sitting in the same commit.

The bech32 `_sized` bullet still says “plain and `_zeroizing`.”

### 3. Merge hygiene with #171 follow-ups

This branch still has the no-alloc `fixed_newtype!` BIP-173 decode hole. `claude/audit-171-followups` is dirty on `fixed_newtype.rs`, `CHANGELOG.md`, `SECURITY.md`, and `fuzz/fuzz_targets/encoding.rs` — the same files #172 touches. Whichever merges second will conflict. If #172 lands first, the #171 follow-ups need a rebase onto it, not onto current `main`.

---

## Not defects (working as designed)

- Extracted values no longer self-wipe. That is the point of Option B. The replacement test is the right one (move, not wipe).
- `EncodedSecret::into_inner` uses `mem::take` through `Zeroizing`’s `DerefMut` and returns an ordinary `String`. Same “protection ends” contract as `RevealSecret::into_inner`.
- Public encodings (addresses, txids) now come back as `EncodedSecret`. Slightly awkward for “this is meant to be logged”; no `Display` still blocks the accident. Callers who want a `String` name `.into_inner()`.
- Downstream `AsRef<[u8]>` types that do not autoderef to `[u8]` cannot get `EncodableBytes` (orphan rule). `.as_ref().to_hex()` / a local newtype is the intended path.

---

I would merge after SECURITY.md, README, the EncodedSecret rustdoc, and the Unreleased changelog are rewritten to the crate that actually exists — especially the extraction contract. The Rust side does not need another design pass.
