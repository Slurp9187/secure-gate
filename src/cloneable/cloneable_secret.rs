//! Cloning utilities for secrets.

/// Marker trait for types that can be safely cloned as secrets.
/// Requires `Clone` for duplication and `Zeroize` for secure wiping.
///
/// Note: This is opt-in; only implement for types where cloning doesn't leak secrets
/// (e.g., primitives, fixed arrays; avoid heap-allocated types like `Vec` or `String`).
/// It's re-exported at the crate root for convenience.
#[cfg(feature = "zeroize")]
pub trait CloneableSecret: Clone + zeroize::Zeroize {
    // Pure marker, no methods
}

#[cfg(feature = "zeroize")]
// Blanket impls for primitives (safe to clone for secrets like keys or nonces)
impl CloneableSecret for i8 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for i16 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for i32 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for i64 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for i128 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for isize {}

#[cfg(feature = "zeroize")]
impl CloneableSecret for u8 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u16 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u32 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u64 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for u128 {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for usize {}

#[cfg(feature = "zeroize")]
impl CloneableSecret for bool {}
#[cfg(feature = "zeroize")]
impl CloneableSecret for char {}

// Blanket for fixed arrays of cloneable secrets (e.g., [u8; 32] AES keys)
#[cfg(feature = "zeroize")]
impl<T: CloneableSecret, const N: usize> CloneableSecret for [T; N] {}
