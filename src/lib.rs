// src/lib.rs
// secure-gate v0.5.1

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

// Core modules
mod dynamic;
mod fixed;
mod macros;

// Feature-gated modules
#[cfg(feature = "zeroize")]
mod zeroize;

#[cfg(feature = "serde")]
mod serde;

// Public API
pub use dynamic::Dynamic;
pub use fixed::Fixed;

// Zeroize integration (opt-in)
#[cfg(feature = "zeroize")]
pub use zeroize::{DynamicZeroizing, FixedZeroizing};

// Re-export Zeroizing cleanly — no privacy conflict
#[cfg(feature = "zeroize")]
pub type Zeroizing<T> = ::zeroize::Zeroizing<T>;

// Re-export the trait and marker directly from the zeroize crate
#[cfg(feature = "zeroize")]
pub use ::zeroize::{Zeroize, ZeroizeOnDrop};
