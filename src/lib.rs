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

// ── Cloneable secret marker (opt-in for safe duplication) ────────────

/// Marker trait for secrets that are safe to clone (e.g., primitives, fixed arrays).
///
/// Implement this for custom types that can be duplicated without security risk.
/// Blanket impls provided for common safe types; others must opt-in.
pub trait CloneableSecret: Clone + zeroize::Zeroize {
    // Pure marker, no methods
}

// Blanket impls for primitives (safe to clone for secrets like keys or nonces)
impl CloneableSecret for i8 {}
impl CloneableSecret for i16 {}
impl CloneableSecret for i32 {}
impl CloneableSecret for i64 {}
impl CloneableSecret for i128 {}
impl CloneableSecret for isize {}

impl CloneableSecret for u8 {}
impl CloneableSecret for u16 {}
impl CloneableSecret for u32 {}
impl CloneableSecret for u64 {}
impl CloneableSecret for u128 {}
impl CloneableSecret for usize {}

impl CloneableSecret for bool {}
impl CloneableSecret for char {}

// Blanket for fixed arrays of cloneable secrets (e.g., [u8; 32] AES keys)
impl<T: CloneableSecret, const N: usize> CloneableSecret for [T; N] {}

// NoClone wrappers removed (replaced by opt-in cloning on base types)

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
