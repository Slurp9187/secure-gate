//! Cloning utilities for secrets.

/// Marker trait for types that can be safely cloned as secrets.
/// Requires `Clone` for duplication and `Zeroize` for secure wiping.
///
/// Note: This is opt-in; only implement for types where cloning doesn't leak secrets
/// (e.g., primitives, fixed arrays; avoid heap-allocated types like `Vec` or `String`).
/// It's re-exported at the crate root for convenience.
#[cfg(feature = "zeroize")]
pub trait CloneableSecretMarker: Clone + zeroize::Zeroize {
    // Pure marker, no methods
}

#[cfg(feature = "zeroize")]
// Blanket impls for primitives (safe to clone for secrets like keys or nonces)
impl CloneableSecretMarker for i8 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for i16 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for i32 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for i64 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for i128 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for isize {}

#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for u8 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for u16 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for u32 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for u64 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for u128 {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for usize {}

#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for bool {}
#[cfg(feature = "zeroize")]
impl CloneableSecretMarker for char {}

// Blanket for fixed arrays of cloneable secrets (e.g., [u8; 32] AES keys)
#[cfg(feature = "zeroize")]
impl<T: CloneableSecretMarker, const N: usize> CloneableSecretMarker for [T; N] {}
