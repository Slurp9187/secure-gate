**Verdict:** Several docs overstate marker gates, Debug behavior after extraction, and “heap-only / never on stack.” Below are **deltas only** for `secure-gate-core` (RustDoc + `README.md` + `SECURITY.md`).

---

### High

1. **`SECURITY.md` § Where accident-prevention ends — Debug example is wrong**  
   Example binds `inner = key.into_inner()` (plain `[u8; N]`), then claims `format!("{:?}", inner)` prints `[REDACTED]`. Reality: redaction is gone after `into_inner`; that `Debug` prints the bytes. Teaches the opposite of the API contract.

2. **`SerializableSecret` / Fixed / Dynamic / SECURITY TL;DR — Deserialize gated by marker**  
   Claim: Serialize/**Deserialize** need marker traits (`CloneableSecret`/`SerializableSecret`).  
   Reality: `Deserialize` is on wrappers via `serde-deserialize` only; marker gates **Serialize** only (`lib.rs` re-export already says this). Same false pairing in `fixed.rs` / `dynamic.rs` security invariants and `SECURITY.md` TL;DR + Core table “Opt-in risky features.”

3. **`serializable_secret.rs` — marker “optionally gates Deserialize”**  
   Module/item docs still say the marker enables Serialize “(and optionally `Deserialize`)”. Code: trait only bounds `Serialize`; Deserialize is independent. Hostile reading: “I implemented the marker, so deserialize is also gated/safe.”

4. **`serializable_secret.rs` — “all copies zeroize on drop” after Serialize**  
   Claim: serialization preserves zeroization / all copies zeroize.  
   Reality: wire/disk output is ordinary non-zeroizing bytes (`SECURITY.md` correctly says this elsewhere). Overclaim vs threat model.

5. **Broken / dead doc links**  
   - `traits/mod.rs`: `…/blob/main/SECURITY.md` → **404** (no repo-root `SECURITY.md`; real path is `secure-gate-core/SECURITY.md`).  
   - `fixed_newtype.rs` / `dynamic_newtype.rs` / `newtype_common.rs`: `docs/nominal_newtypes.md` → **missing**.

---

### Medium

6. **Stale “read-only wrappers / random types”** (`reveal_secret.rs`, `reveal_secret_mut.rs`, `traits/mod.rs`)  
   Claim: encoding wrappers and random generators implement only `RevealSecret`.  
   Reality: `EncodedSecret` does **not** implement `RevealSecret` (Deref/`into_*` only); there are no separate “random types” as RevealSecret implementors—only `from_random` constructors on Fixed/Dynamic.

7. **`reveal_secret_mut.rs` module doc — length inherited from `RevealSecret`**  
   Claim: you automatically get `.len()` / `.is_empty()` from `RevealSecret`.  
   Reality: those live on `SecretLen` (trait docs below are correct; module header is stale).

8. **`Dynamic` “heap-only / secret bytes never on the stack”** (`dynamic.rs`, echoed in `SECURITY.md` mitigations)  
   Absolute “never” is false for `Dynamic::new` / `From<T>` (value may exist on stack before `Box::new`) and for `into_inner` (returns `T` by value). Decode/`from_protected_bytes` paths are the ones that justify the stronger wording.

9. **`lib.rs` EncodedSecret re-export vs crate prose**  
   Re-export: `into_zeroizing` “preserve[s]” protection.  
   Crate docs / `SECURITY.md` earlier: Debug redaction is **lost**. Soft contradiction; escape-hatch section later in `SECURITY.md` again says only “preserves zeroization” and omits the Debug downgrade.

10. **`revealed_secrets/mod.rs` — `into_zeroizing` keeps “radioactive” guarantees**  
    Overstates: zeroize-on-drop remains; redacted `Debug` does not.

11. **`SECURITY.md` feature table — `std` “no additional security surface beyond `alloc`”**  
    Reality: `as_reader` copies secrets into caller buffers; `Write` has special growth-zeroize behavior. That is a material surface.

12. **`README.md` Encoding intro — “All operations … return `Result` on failure”**  
    Reality: `to_hex` / `to_hex_upper` / `to_base32` / `to_base64url` are infallible; only Bech32/m (and decodes) are `Result`.

13. **`README.md` Quick Start — `Aes256Key::from_random()` ungated**  
    Needs `rand`. Doctest only runs under `full`, so CI is fine; default-feature readers following the README get a compile miss.

14. **`README.md` — “All constructors guarantee zeroization even on OOM via Zeroizing”**  
    Overbroad: decode/`from_protected_bytes` paths yes; `Fixed::new` / plain `Dynamic::new` are not that pattern.

15. **`SECURITY.md` Core table — “Debug impl always prints `[REDACTED]`”**  
    Unscoped. True for Fixed/Dynamic/EncodedSecret; false for errors, checksum helpers, etc., and false after extraction.

16. **`fixed.rs` — Debug redaction covers “logs or panic messages”**  
    Only `Debug` of the wrapper. Panics/`Display`/caller formatting of extracted data are out of scope.

17. **`constant_time_eq.rs` opener vs later caveat**  
    Opener: time independent of data. Later: length mismatch short-circuits. Absolute top claim is overstated (length caveat is correct).

18. **Audit surface lists incomplete vs own guidance**  
    - `SECURITY.md` audit grep block: missing `as_reader`, `into_zeroizing`, `try_from_*`.  
    - `README.md` audit list: has `as_reader`, still misses `into_zeroizing`.

19. **`SECURITY.md` markdown** — Fixed/Dynamic docs.rs links wrapped in backticks → rendered as literal text, not links.

---

### Low

20. **`CloneableSecret` / traits table — “safe cloning”**  
    Cloning expands exposure; “safe” is soft-sell vs the rest of the threat model.

21. **`SECURITY.md` typo** — `ZeroizingOnDrop` (should be `ZeroizeOnDrop`).

22. **`hex.rs` Security Notes** — “validate hex strings upstream” under an **encode** trait (decode guidance misplaced).

23. **Marketing “zero-overhead / zero-cost”** (crate root, README, encoding section)  
    Abstraction cost is low; encode still allocates `String` / `EncodedSecret`. Easy to misread as “no memory cost.”

24. **`reveal_secret.rs` implementor note** — suggests `unimplemented!()` for `into_inner` on borrow-only wrappers; no such public wrappers exist today (stale design note).
