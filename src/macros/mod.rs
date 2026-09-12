//! Macros for nominal newtype secret types.
//!
//! [`fixed_newtype!`] and [`dynamic_newtype!`] create domain-specific secret
//! types (e.g., `Aes256Key`, `Password`) that inherit all security guarantees
//! from [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic): zeroize on
//! drop, redacted `Debug`, explicit access only.
//!
//! # Newtype or plain `type`?
//!
//! Naming a secret does not need a macro. A plain Rust `type` alias gives a
//! readable name whose every guarantee is the wrapper's own, because the named
//! type *is* the wrapper, and it stays interchangeable with its base, so it
//! crosses into APIs you do not own without ceremony. Two such aliases over
//! the same shape (two names for `Fixed<[u8; 32]>`, say) resolve to the
//! **same** nominal type and are freely assignable to each other: an alias is
//! a readability and audit-grep device, not compile-time separation between
//! cryptographic roles.
//!
//! A newtype emits a `struct`, so two newtypes of the same shape are
//! **distinct** types and passing an encryption key where a MAC key belongs is
//! a compile error rather than a silent bug. Use these when distinct roles
//! share a shape — the common cases being `Fixed<[u8; 32]>` for two different
//! keys, or `Dynamic<String>` for two different credentials.
//!
//! Write a `type` when a name is all you want, and a newtype when the compiler
//! should enforce the role. Earlier releases shipped `fixed_alias!`,
//! `dynamic_alias!`, `fixed_generic_alias!` and `dynamic_generic_alias!`
//! macros that expanded to exactly that one `type` line; they were removed in
//! this release, and
//! [CHANGELOG.md](https://github.com/Slurp9187/secure-gate/blob/release/0.8/CHANGELOG.md)
//! carries the reasoning and a migration table.
//!
//! | Written as                     | Generates                     | Nominal? | Feature |
//! |--------------------------------|-------------------------------|----------|---------|
//! | `type Name = Fixed<[u8; N]>;`  | a second name for the wrapper | No       | Always  |
//! | `type Name = Dynamic<T>;`      | a second name for the wrapper | No       | `alloc` |
//! | [`fixed_newtype!`]             | `struct` over `Fixed<[u8; N]>`, or over `Fixed<T>` with `generic T` | **Yes** | Always |
//! | [`dynamic_newtype!`]           | `struct` over `Dynamic<T>`, or the same with `generic T` | **Yes** | `alloc` |
//!
//! The `generic T` form of either macro is for an inner type that is neither a
//! byte array nor a `String` — an `[i16; 256]` polynomial, a `Vec<u32>` of
//! counters — and emits only the surface that is meaningful for an arbitrary
//! `T`.
//!
//! # Security note
//!
//! [`fixed_newtype!`] rejects `N = 0` at the declaration, and
//! [`Fixed`](crate::Fixed) itself rejects a zero-sized inner value at
//! construction: `Fixed::new` and `Fixed::new_with` carry a `const`
//! assertion, so a plain `type` alias and the `generic T` arm are covered too.
//! [`dynamic_newtype!`] has no compile-time equivalent — a `Dynamic` is
//! pointer-sized whatever it holds — so validate lengths that come from
//! configuration in your own tests.
//!
//! Newtypes generate no `From<Wrapper>` and no `Deref`, so a base-typed value
//! (any plain `type` alias included) cannot become a newtype through `.into()`
//! and a newtype never coerces back to its base. Base-wrapper access is opt-in
//! per newtype and split by direction: `derive: [FromWrapper]` lets a base
//! value enter the role, `derive: [IntoWrapper]` lets material leave toward
//! the base; `WrapperAccess` is both. In a mixed tree the base type is the
//! pool every plain alias lives in, so `FromWrapper` on a boundary type
//! accepts all of them, and `IntoWrapper` on a secret role downgrades it to
//! the least-sensitive alias sharing its base. Neither token is the sufficient
//! default more often than it looks. Audit these as you would
//! `expose_secret()`.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{fixed_newtype, Fixed, RevealSecret, SecretLen};
//!
//! // A plain `type` alias — a readable name for one shape.
//! type Aes256Key = Fixed<[u8; 32]>;
//! let key: Aes256Key = [0u8; 32].into();
//! key.with_secret(|b| assert_eq!(b.len(), 32));
//!
//! // Newtypes — two roles the compiler keeps apart.
//! fixed_newtype!(pub EncKey, 32);
//! fixed_newtype!(pub MacKey, 32);
//!
//! fn seal(_enc: &EncKey, _mac: &MacKey) {}
//! seal(&EncKey::new([1u8; 32]), &MacKey::new([2u8; 32]));
//! // seal(&MacKey::new(..), &EncKey::new(..)) would not compile.
//! assert_eq!(EncKey::new([1u8; 32]).len(), 32);
//! ```
mod dynamic_newtype;
mod fixed_newtype;
mod newtype_common;
