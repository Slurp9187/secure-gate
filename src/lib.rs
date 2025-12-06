// ==========================================================================
// src/lib.rs
// ==========================================================================

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

extern crate alloc;

mod dynamic;
mod fixed;
pub mod macros;

pub mod no_clone;
pub use no_clone::{DynamicNoClone, FixedNoClone};

#[cfg(feature = "serde")]
mod serde;

#[cfg(feature = "conversions")]
pub mod conversions;

#[cfg(feature = "rand")]
pub mod rng;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

#[cfg(feature = "conversions")]
pub use conversions::{HexString, RandomHex, SecureConversionsExt};
