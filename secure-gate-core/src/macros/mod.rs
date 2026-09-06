//! Convenience macros for naming secure secret wrappers.
//!
//! These macros create domain-specific secret types (e.g., `Aes256Key`,
//! `Password`) that inherit all security guarantees from
//! [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic): zeroize on drop,
//! redacted `Debug`, explicit access only.
//!
//! # Aliases or newtypes?
//!
//! The two families differ in exactly one respect — whether the compiler can
//! tell two same-shaped secrets apart:
//!
//! - **`*_alias!`** emits a plain Rust `type` alias. Two aliases over the same
//!   underlying type (e.g. two `fixed_alias!` invocations with the same `N`)
//!   resolve to the **same** nominal type and are freely assignable to each
//!   other. Aliases improve readability and give you audit grep targets; they
//!   provide no compile-time separation between cryptographic roles.
//! - **`*_newtype!`** emits a `struct`. Two newtypes of the same shape are
//!   **distinct** types, so passing an encryption key where a MAC key belongs
//!   is a compile error rather than a silent bug. Use these when distinct
//!   roles share a shape — the common cases being `Fixed<[u8; 32]>` for two
//!   different keys, or `Dynamic<String>` for two different credentials.
//!
//! Reach for an alias when a name is all you want, and a newtype when the
//! compiler should enforce the role.
//!
//! | Macro                     | Generates                     | Nominal? | Feature |
//! |---------------------------|-------------------------------|----------|---------|
//! | [`fixed_alias!`]          | `Fixed<[u8; N]>` alias        | No       | Always  |
//! | [`fixed_generic_alias!`]  | `Name<const N: usize>` alias  | No       | Always  |
//! | [`dynamic_alias!`]        | `Dynamic<T>` alias            | No       | `alloc` |
//! | [`dynamic_generic_alias!`]| `Name<T>` alias               | No       | `alloc` |
//! | [`fixed_newtype!`]        | `struct` over `Fixed<[u8; N]>`| **Yes**  | Always  |
//! | [`dynamic_newtype!`]      | `struct` over `Dynamic<T>`    | **Yes**  | `alloc` |
//!
//! # Security note
//!
//! [`fixed_alias!`] and [`fixed_newtype!`] are the **only** macros with a
//! compile-time zero-size guard (`N = 0` is a compile error). The others allow
//! zero-sized inner types — validate expected sizes in tests.
//!
//! Newtypes generate no `From<Wrapper>` and no `Deref`, so an alias-typed value
//! cannot become a newtype through `.into()` and a newtype never coerces back to
//! its base. Base-wrapper access (`from_wrapper`, `as_wrapper`, `into_wrapper`)
//! exists only with `derive: [WrapperAccess]`, per newtype — it can move a secret
//! between roles deliberately, so audit it as you would `expose_secret()`.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{fixed_alias, fixed_newtype, RevealSecret, SecretLen};
//!
//! // Alias — a readable name for one shape.
//! fixed_alias!(pub Aes256Key, 32);
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
mod dynamic_alias;
mod dynamic_generic_alias;
mod dynamic_newtype;
mod fixed_alias;
mod fixed_generic_alias;
mod fixed_newtype;
mod newtype_common;
