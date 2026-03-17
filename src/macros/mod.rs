//! Convenience macros for creating type aliases to secure secret wrappers.
//!
//! All macros generate zero-cost type aliases. The compile-time zero-size guard in
//! [`fixed_alias!`] and const-generic variants is the only automated size validation —
//! always validate expected sizes in unit tests.
//!
//! | Macro                   | Generates                   | Feature   |
//! |-------------------------|-----------------------------|-----------|
//! | [`fixed_alias!`]        | `Fixed<[u8; N]>` alias      | Always    |
//! | [`fixed_generic_alias!`]| `Name<const N: usize>` alias| Always    |
//! | [`dynamic_alias!`]      | `Dynamic<T>` alias          | `alloc`   |
//! | [`dynamic_generic_alias!`]| `Name<T>` alias           | `alloc`   |
mod dynamic_alias;
mod dynamic_generic_alias;
mod fixed_alias;
mod fixed_generic_alias;
