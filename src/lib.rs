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
pub mod traits;

// The One True Type
pub use secure_gate::SecureGate;

/// Short prefix
pub type SG<T> = SecureGate<T>;

// Public re-exports
// pub use crate::secure; // macro_export lives at crate root
pub use aliases::*;

// Fixed-size stack secrets — only when feature = "stack"
#[cfg(feature = "stack")]
pub mod fixed_stack;
#[cfg(feature = "stack")]
pub mod fixed {
    pub use crate::fixed_stack::*;
}

// Legacy bridge — keeps every test and old user alive
pub use deprecated::*;

// Re-export traits directly from secrecy when zeroize is on
#[cfg(feature = "zeroize")]
pub use secrecy::{ExposeSecret, ExposeSecretMut};

// Fallback traits when zeroize is off (from your original lib.rs)
#[cfg(not(feature = "zeroize"))]
pub use traits::{ExposeSecret, ExposeSecretMut};
