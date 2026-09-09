Your checker is the one that’s wrong. The code fix is real. The pin is weaker than the changelog says.

---

## 1. Finding 1 — fixed, not moved

The constructors are a **sibling** of the alloc gate, not still inside it:

```378:411:secure-gate-core/src/macros/fixed_newtype.rs
        $crate::__sg_if_bech32! {
            $crate::__sg_if_alloc! {
                impl $crate::ToBech32 for $name { /* encode only */ }
            }
            impl $name {
                pub fn try_from_bech32(...) { ... }
                pub fn try_from_bech32_unchecked(...) { ... }
                pub fn try_from_bech32_sized(...) { ... }
                pub fn try_from_bech32_unchecked_sized(...) { ... }
            }
        }
```

That matches the bech32m block above it. Two `impl $name` blocks (one per checksum) is legal; the methods don’t overlap.

I compiled both combos:

| Features | Result |
|---|---|
| `--no-default-features --features encoding-bech32` | `nostd_newtype_decodes_both_checksums` **ran and passed** |
| `--no-default-features --features alloc,encoding-bech32` | compiled; pin test cfg’d out; **no E0119 duplicate impl** |

A checker that still reports them as alloc-gated is matching “inside `__sg_if_bech32!`, and an `__sg_if_alloc!` appears first.” That’s the encode impl. The decode `impl $name` starts after that gate closes at line 410.

**Two caveats on the pin, not on the fix:**

- Changelog says it “pins all eight.” The test names **four** (`try_from_bech32{,m}{,_unchecked}`). The `_sized` four live in the same `impl` so they come along, but a later split would not be caught. Those `_sized` methods are the ones #171 originally dropped.
- **CI never runs this cfg.** The encoding-bech32 matrix row is `alloc,encoding-bech32`. The no-std job is `--lib` only, so it never expands a consumer `fixed_newtype!`. The pin is local-only unless you add that row later.

You actually fixed it. The checker’s report is the earlier, legitimate encode gate.

---

## 2. `dynamic_newtype!` — not the same bug

The whole macro is `#[cfg(feature = "alloc")]` at definition time. `Dynamic` cannot exist without alloc, so there is no no-alloc consumer to strand.

On the `Vec<u8>` arm, bech32 and bech32m are already symmetric: decode constructors and `ToBech32`/`ToBech32m` sit together under `__sg_if_bech32!` / `__sg_if_bech32m!` with **no nested alloc gate**. That’s the shape `fixed_newtype!` just reached. Leaving it alone was correct.

---

## 3. ASan feature set — plausible CI red, right change

I cannot run `x86_64-unknown-linux-gnu` + `-Z build-std` + ASan on this Windows host, so this is a risk call, not a green check.

You didn’t only turn on bech32. Hex, base32, and base64 heap oracles in `heap_zeroize.rs` were **also** compiled out of ASan before (`--features alloc` only). They already run under the ProxyAllocator in the encoding matrix rows; ASan+LSan is a different interceptor.

Most likely red if it goes red: LSan on a dependency (`bech32` / `*ct`) or `build-std` noise, not a logic bug in the feature list. If that happens it’s yours to triage, but I wouldn’t shrink the feature set back — that would re-blind the oracles this PR exists to light.

---

## 4. Same-class twins still sitting on `4185cf3..main`

This PR’s own twins look closed: all three default-path fuzz `expect`s, both unchecked `# Errors` lists, SECURITY.md 1023 note.

Leftovers from #171 of the “fixed the one I was looking at” shape:

| Twin | What landed | Sibling |
|---|---|---|
| Default proptest payload cap | bech32 `0..=255` | bech32m still `0..=90` (the old address convention that was never enforced) |
| Fuzz unchecked Fixed | `Fixed::<[u8; 4]>::try_from_bech32_unchecked` in 4a | 5a is Dynamic-only for bech32m |
| Encoder-chain size pin | `encoder_chain_carries_no_staging_buffer` in `encoding/bech32.rs` | bech32m has the equivalence test, not the `size_of_val` pin |
| CI `encoding-bech32` without `alloc` | still no host test job | you already called this out as deliberate |

None of those is another missing constructor. The proptest 90-byte cap is the closest real twin: after the default became 1023, bech32’s default-path property was widened and bech32m’s wasn’t. It’s coverage, not an API hole.

The remaining `if let Ok(at_default) = capped.try_to_bech32("fuzz")` in the sized fuzz path is the legitimate one — 2048-byte payloads can exceed 1023. Leave it.

---

**Merge call on these four:** ship it. If you touch anything, make the pin test name the four `_sized` methods and/or put `--no-default-features --features encoding-bech32` on a host job so CI actually expands that `fixed_newtype!`. That’s the only way finding 1’s class stays closed after the next macro edit.
