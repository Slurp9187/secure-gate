Read-only audit of [PR #171](https://github.com/Slurp9187/secure-gate/pull/171) as landed on `main` (`61a5bd3`). This is not a review of the dirty `claude/handoff-semantics` worktree.

**Verdict:** the refactor’s core holds. `N` is a length gate, the checksums stay BIP-173 / BIP-350, the encoder no longer grows through unwiped reallocs, and post-merge CI (feature matrix, encoding fuzz, ASan for the non-bech32 heap suite) is green. I did not find a checksum or “unwiped realloc copy” regression. A few real holes remain, all around API completeness, docs, and test oracles.

---

## What holds

The important claims check out against the code:

- **`Bech32Sized<N>` / `Bech32mSized<N>` do not mix `N` into the checksum.** Generator coefficients and target residues match upstream (`1` vs `0x2bc830a3`). Tests prove byte-identical output at every admitting `N`, including the default 1023 path.
- **Default 1023 is the right BCH bound.** The old `CODE_LENGTH = 8191` / `Bech32Large` story was a silent stretch of a 30-bit checksum. Forcing large payloads through `_sized::<N>` is the honest API.
- **The heap-grow leak is actually closed.** `bech32_code_length` is exact (saturating, not wrapping), the encoder reserves that length, then drives `bytes_to_fes → with_checksum → chars` into the buffer. Equivalence vs `encode_lower` is pinned; `helper_is_exact_not_approximate` proves `N` is the smallest value that works.
- **HRP-before-payload-bytes is real, not just comment-shaped.** `try_from_bech32_sized` compares HRP before `byte_iter().collect()`, and `heap_zeroize` counts allocations on mismatch (with a successful-Vec positive control). `Fixed` still drains into `Zeroizing<[u8; N]>` and wipes on length mismatch.
- **The nine adversarial findings they listed look actually fixed** in the landed tests: achievable stress rungs, sized decoders on newtypes (under `alloc`), saturating `bech32_code_length`, fuzz sized-path `expect` instead of swallowed `Err`.
- **Feature fold is consistent** in `Cargo.toml` / `__sg_if_bech32m!` (both keyed off `encoding-bech32`). Errors stay `Copy` and carry no HRP or payload.

---

## Findings

| Severity | Location | Finding |
|---|---|---|
| Medium | `fixed_newtype.rs` (~L378) | BIP-173 decode on generated newtypes is gated on `alloc`; BIP-350 is not. `no_std` + `encoding-bech32` gets `try_from_bech32m*` and loses `try_from_bech32*`. |
| Medium | `.github/workflows/ci.yml` ASan job | ASan `heap_zeroize` runs `--features alloc` only, so the new bech32 HRP-mismatch and decode-zeroize oracles never run under ASan. |
| Low | `fuzz/fuzz_targets/encoding.rs` §4b/4d/5b | Default-path encode still uses `if let Ok` for cases that cannot legitimately fail (`"fuzz"` HRP, tiny payloads). Sized path was fixed; default path was not. |
| Low | `decoding/bech32.rs` L9; CHANGELOG; `SECURITY.md` | Stale / conflicting docs after the fold and the encoder rewrite. |
| Low | `bech32_sized.rs` capacity oracle | `capacity() == len()` is an allocator-size-class check, not a proof that no copy was left behind. It passed on Ubuntu this time. |

### 1. `fixed_newtype!` drops no-alloc BIP-173 decode

`Fixed::try_from_bech32*` is intentionally alloc-free. Bech32m decode is forwarded the same way. BIP-173 decode was stuffed inside the `ToBech32` (String) gate:

```378:436:secure-gate-core/src/macros/fixed_newtype.rs
        $crate::__sg_if_bech32! {
            $crate::__sg_if_alloc! {
                impl $crate::ToBech32 for $name { /* encode */ }
                impl $name {
                    pub fn try_from_bech32(...) { ... }
                    pub fn try_from_bech32_sized(...) { ... }
                    // ...
                }
            }
        }
```

Bech32m decode sits *outside* `__sg_if_alloc!`. After the feature fold both macros fire on `encoding-bech32`, so a no-alloc newtype can decode bech32m and cannot decode bech32. `lib.rs` still advertises `Fixed::try_from_bech32` without `alloc`. CI never runs `encoding-bech32` without `alloc` (the PR already listed that as a known gap), so this could not have been caught.

This is the leftover of “macros forwarded sized encoders but not decoders”: they fixed the alloc world (and `newtype_forwards_sized_bech32_decode` covers it) and missed the no-alloc world the crate otherwise supports.

### 2. ASan does not actually instrument the new bech32 heap tests

```368:377:.github/workflows/ci.yml
      - name: Run heap_zeroize with AddressSanitizer
        run: >
          cargo +nightly test
          --features alloc
          --test heap_zeroize
```

`check_bech32_hrp_mismatch_materializes_nothing` and the bech32 decode-zeroize helpers are all `#[cfg(feature = "encoding-bech32")]`. The ProxyAllocator path runs in the encoding-bech32 matrix row; ASan does not. For a PR whose security story is “no extra copies of the secret,” that’s the wrong sanitizer config.

### 3. Fuzz default path still swallows impossible `Err`

Sized encode now `expect`s, which is the adversarial fix. The default path is still:

```rust
if let Ok(encoded) = capped.try_to_bech32("fuzz") { ... }
if let Ok(encoded) = b"hello".try_to_bech32("mykey") { ... }
```

`"fuzz"` / `"mykey"` are valid HRPs and the payloads are far under 1023 characters. `Err` here can only be a regression, and it is still skipped. Same shape on default bech32m (32-byte cap).

### 4. Docs drift

- `decoding/bech32.rs` still says the feature is “(distinct from Bech32m)”. After the fold that sentence is false.
- Unchecked-path `# Errors` still talks about “bit-conversion failure” as if it were a separate class; `ConversionFailed` is gone and that case is `OperationFailed`.
- CHANGELOG still describes the encoder as writing through `encode_lower_to_fmt`. A later commit in the same PR abandoned that because of the 1 KiB stack staging buffer. Landed code drives the iterator chain.
- `SECURITY.md` never mentions the 1023 bound, `_sized`, or that `N > 1023` forfeits the BCH detection guarantee.
- “Already-encoded strings are unaffected” is true for the checksum and false for the default methods: a stored string longer than 1023 now needs `_sized` to decode. The migration paragraph above it is accurate; that one sentence is the easy misread.

### 5. `capacity() == len()` as a wipe oracle

`String::with_capacity(n)` only guarantees `capacity >= n`. Spare capacity from size-class rounding is not an unwiped prefix of the secret. The test is a useful canary when it fails, and a lucky allocator when it passes. The real guards are the exact `bech32_code_length` check plus the upstream-equivalence test.

---

## Threat-model notes (not defects)

These are working as designed; calling them out so they aren’t mistaken for misses:

- **`N > 1023` is a weakened checksum.** Still computed, no proven 4-error bound. One-character-corruption tests at 900 bytes passing is luck of a 30-bit residue, not a restored BCH guarantee. The type docs say this.
- **Plain `try_to_bech32` returns an ordinary `String`.** The realloc leak is gone; the buffer is still not wiped unless you take `_zeroizing`. That matches hex/base32/base64.
- **HRP compare is not constant-time.** Documented; HRP is public.
- **`FromBech32Str` still returns a naked `Vec<u8>`.** Wrappers (`Fixed` / `Dynamic`) are the zeroizing path.
- **Miri is not a PR check.** `.github/workflows/fuzz-miri.yml` is `push: main` + weekly cron, not `pull_request`. The PR body treated Miri as part of “this PR’s first CI run”; it would only start after merge.

---

## Suggested follow-ups (not doing them; this was read-only)

1. Lift `try_from_bech32*` out of `__sg_if_alloc!` in `fixed_newtype!`, matching the bech32m block. Add a `no_std` + `encoding-bech32` compile test that a newtype can call them.
2. Run ASan `heap_zeroize` with `--features alloc,encoding-bech32` (and the other encoding features the test already cfg-gates).
3. Change default-path fuzz encode to `expect`, same as the sized path.
4. Delete the “distinct from Bech32m” clause; fix the CHANGELOG encoder sentence; mention 1023 / `_sized` in `SECURITY.md`.

I would not block on (2)–(4). I would treat (1) as a real API bug in a crate that otherwise ships no-alloc `Fixed` bech32 decode.
