//! Convenience macros for creating typed aliases to secure secret wrappers.
//!
//! These macros create domain-specific newtype aliases (e.g., `Aes256Key`, `Password`)
//! that inherit all security guarantees from [`Fixed`](crate::Fixed) or
//! [`Dynamic`](crate::Dynamic): zeroize on drop, redacted `Debug`, explicit access only.
//!
//! | Macro                   | Generates                   | Feature   |
//! |-------------------------|-----------------------------|-----------|
//! | [`fixed_alias!`]        | `Fixed<[u8; N]>` alias      | Always    |
//! | [`fixed_generic_alias!`]| `Name<const N: usize>` alias| Always    |
//! | [`dynamic_alias!`]      | `Dynamic<T>` alias          | `alloc`   |
//! | [`dynamic_generic_alias!`]| `Name<T>` alias           | `alloc`   |
//!
//! # Security note
//!
//! [`fixed_alias!`] is the **only** macro with a compile-time zero-size guard (`N = 0`
//! is a compile error). All others allow zero-sized types — validate `N > 0` in tests.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{fixed_alias, RevealSecret};
//!
//! fixed_alias!(pub Aes256Key, 32);
//! let key: Aes256Key = [0u8; 32].into();
//! key.with_secret(|b| assert_eq!(b.len(), 32));
//! ```
mod dynamic_alias;
mod dynamic_generic_alias;
mod fixed_alias;
mod fixed_generic_alias;
