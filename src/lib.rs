// src/lib.rs
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
extern crate alloc;

mod dynamic;
mod fixed;

#[cfg(feature = "zeroize")]
mod zeroize;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

#[cfg(feature = "zeroize")]
pub use zeroize::{DynamicZeroizing, FixedZeroizing};
