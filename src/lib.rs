// ==========================================================================
// src/lib.rs
// ==========================================================================

// Allow unsafe_code when conversions or zeroize is enabled (conversions needs it for hex validation)
#![cfg_attr(
    not(any(feature = "zeroize", feature = "conversions")),
    forbid(unsafe_code)
)]
#![doc = include_str!("../README.md")]

extern crate alloc;

// ── Core secret types (always available) ─────────────────────────────
mod dynamic;
mod fixed;

pub use dynamic::Dynamic;
pub use fixed::Fixed;

// ── Non-cloneable wrappers (always available, zero-cost, pure) ───────
mod no_clone;
pub use no_clone::{DynamicNoClone, FixedNoClone};

// ── Macros (always available) ────────────────────────────────────────
mod macros;

// ── Feature-gated modules (zero compile-time cost when disabled) ─────
#[cfg(feature = "rand")]
pub mod rng;

// conversions module is needed for ct-eq feature (SecureConversionsExt trait)
#[cfg(any(feature = "conversions", feature = "ct-eq"))]
pub mod conversions;

// ── Feature-gated re-exports ─────────────────────────────────────────
#[cfg(feature = "rand")]
pub use rng::{DynamicRng, FixedRng};

#[cfg(feature = "conversions")]
pub use conversions::HexString;

#[cfg(any(feature = "conversions", feature = "ct-eq"))]
pub use conversions::SecureConversionsExt;

#[cfg(all(feature = "rand", feature = "conversions"))]
pub use conversions::RandomHex;
