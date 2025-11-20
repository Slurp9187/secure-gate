// src/lib.rs
//
// Core secure wrapper types and traits — secure-gate 0.4.0+
// Unified public API built on SecureGate<T>

#![no_std]
#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

// Public modules
pub mod aliases;
pub mod deprecated;
pub mod macros;
pub mod secure_gate;

// The One True Type
pub use secure_gate::SecureGate;

/// Short prefix
pub type SG<T> = SecureGate<T>;

// Public re-exports
pub use aliases::*;

// Legacy bridge — keeps every test and old user alive
pub use deprecated::*;

// Re-export secrecy traits when zeroize is enabled
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};
