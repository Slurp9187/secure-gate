# secure-gate newtyping — requirements from encrypted-file-vault

Context: EFV is a downstream consumer with 34 aliases in `crates/efv-core/src/aliases.rs`.
We hit a concrete security-design failure because those aliases are synonyms, not types.
Cross-check these against what you've planned/built.

## The problem, measured

Both alias macros expand to a plain `type` alias:

    dynamic_alias!  ->  $vis type $name = $crate::Dynamic<$inner>;
    fixed_alias!    ->  $vis type $name = $crate::Fixed<[u8; $size]>;

So 34 aliases collapse to 8 real types. Consequences in our tree:

- 20 aliases share `Dynamic<String>`. `FileId` (documented "never crosses IPC")
  and `PublicId` (documented "safe to expose via Tauri IPC") are the SAME TYPE,
  on adjacent lines, with comments asserting opposite security properties.
  `MasterPassword`, `UserPassphrase`, `FilePassword` and `TotpSecret` are also
  that same type — as are `Status`, `MimeType` and `OpType`.
- WORSE, the fixed case: `FileKey32`, `VaultKey32`, `IndexKey32`, `MasterKemSeed`
  and `SidecarKey32` are all `Fixed<[u8; 32]>`. Five distinct cryptographic
  purposes, mutually substitutable. Passing a vault master key where a per-file
  key belongs compiles silently.
- `Salt16`, `Tag16` and `RandomDiceware` are all `Fixed<[u8; 16]>`.

This defeated a security design: we wanted an IPC-facing field typed `PublicId`
to structurally refuse a `FileId`. It cannot, because they are one type.

## Requirements

### R1 — Distinct type identity, for BOTH Dynamic and Fixed
Fixed matters at least as much as Dynamic; see the key-confusion case above.

### R2 — Controlled conversion (THE critical requirement)
If the macro derives `From<Dynamic<String>>` / `From<Fixed<[u8; N]>>`, or offers
a blanket unwrap-rewrap, substitution returns through a one-line `.into()` and
the distinctness buys nothing.

Conversions between newtypes, and between a newtype and its base, must be
EXPLICIT and GREPPABLE. Our preference: no cross-newtype conversion at all —
force a trip through `with_secret` — or `TryFrom` with a stated reason. If you
provide `From`, please gate it behind something opt-in per newtype.

This is the requirement most likely to be got wrong by accident, and it is the
one that decides whether the feature is worth adopting.

### R3 — No `Deref` to the base type
`Deref<Target = Dynamic<T>>` would coerce a newtype back into the synonym pool at
any call site expecting the base. Same failure as R2 by another route.

### R4 — Preserve everything the wrapper already gives
Zeroize on drop; `Debug` printing `[REDACTED]`; NO `Display`; the full 3-tier
access (`with_secret` / `expose_secret` / `into_inner`). We are not trading
safety for type identity — a newtype should be strictly additive.

### R5 — Opt-in `Serialize`, per newtype
Today `Dynamic<T>: Serialize` requires `T: SerializableSecret`, and our workspace
has ZERO impls, so no secure-gate type can be serialized at all. That is a good
default. But a newtype meant to cross an IPC boundary needs a deliberate way to
say so — and it must be per-newtype, not per base type, or enabling it for one
enables it for every alias sharing that base.

Concretely: `PublicId` is documented as safe to expose and must serialize;
`FileId` shares its base type and must never serialize. Under the current design
that distinction is unexpressible.

### R6 — Coexist with the existing alias macros
We will NOT newtype all 34. Only the ones where substitution is a security event
(`PublicId`, and the key/password family) are worth the churn; the descriptive
ones (`Status`, `MimeType`, `OpType`, `SettingKey`) can stay plain aliases.
`newtype!` and `dynamic_alias!`/`fixed_alias!` must work side by side in one file.

### R7 — Construction and access shape
We shipped an interim hand-written newtype so we could stop waiting. Matching
this shape means our call sites do not move twice:

    pub struct PublicId(SecureString);          // private field, no Deref

    impl PublicId {
        pub fn new(value: impl Into<String>) -> Self { ... }
    }

    impl RevealSecret for PublicId {
        type Inner = String;
        fn with_secret<F, R>(&self, f: F) -> R where F: FnOnce(&String) -> R;
        fn expose_secret(&self) -> &String;
        fn len(&self) -> usize;
        fn into_inner(self) -> secure_gate::InnerSecret<String>;
    }

    impl core::fmt::Debug for PublicId { /* "[REDACTED]" */ }

Result: 20 call sites compiled UNCHANGED, and substituting a `FileId` now fails
with `expected PublicId, found Dynamic<String>`. If your macro generates a
different constructor or accessor name, say so and we will adapt — we just want
to know before, not after.

## Questions

1. What is the macro's name and syntax? Does it take the same
   `(vis, name, inner)` / `(vis, name, size)` shape as the alias macros?
2. How is conversion spelled (R2)? Is there any blanket `From`/`Into`?
3. Is `Deref` implemented (R3)?
4. Can a single newtype opt into `Serialize` without its base type or siblings
   gaining it (R5)?
5. Does it cover `Fixed` as well as `Dynamic` (R1)?
6. Is there a migration path from `pub type X = SecureString` that does not
   require touching every call site?
7. Do newtypes over the same base remain mutually incompatible in generic
   contexts (e.g. a `fn f<T: RevealSecret<Inner = String>>` would still accept
   both — is that intended)?

## Priority

R2 > R1 > R5 > R3 > R4 > R6 > R7.

R2 first because a newtype with a blanket `From` is documentation, not
enforcement — which is exactly the state we are trying to leave.