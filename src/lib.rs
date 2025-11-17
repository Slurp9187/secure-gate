
// src/lib.rs
//
// Re-export secure wrappers with backward compat

#![no_std]
#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod heap;
pub mod stack;
pub mod macros;
// REMOVED: pub mod secure_types;

pub use heap::HeapSecure as Secure;  // Backward compat: Secure<T> = HeapSecure<T>
#[cfg(feature = "stack")]
pub use stack::*;

// Re-export secrecy traits when zeroize is enabled
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};