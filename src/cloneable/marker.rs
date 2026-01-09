//! Marker trait and implementations for types that can be safely cloned as secrets.
//!
//! This module defines the [`CloneableSecretMarker`] trait and provides blanket
//! implementations for primitive types and fixed-size arrays that are safe to clone
//! when handling sensitive data. The trait ensures that only types meeting the
//! security requirements (Clone + Zeroize) can be used in cloneable secret wrappers.

/// Marker trait for types that can be safely cloned when used as secrets.
///
/// Types implementing this trait guarantee that:
/// - They can be cloned without leaking sensitive information
/// - They implement `Zeroize` for secure memory wiping
/// - They are suitable for use in cryptographic contexts
///
/// # Safety
///
/// This trait is intentionally restrictive. Only implement it for types where cloning
/// is guaranteed not to leak secrets. Safe examples include primitives and fixed-size
/// arrays. Avoid implementing for heap-allocated types like `Vec` or `String` unless
/// you're certain cloning won't compromise security.
///
/// This trait is re-exported at the crate root for convenience.
#[cfg(feature = "zeroize")]
pub trait CloneableSecretMarker: Clone + zeroize::Zeroize {
    // Pure marker, no methods
}

#[cfg(feature = "zeroize")]
// Blanket implementations for primitive types that are safe to clone as secrets.
// These include integer types commonly used in cryptographic operations like
// keys, nonces, counters, and other small fixed-size values.
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

// Blanket implementation for fixed-size arrays of cloneable secret types.
// This allows arrays like [u8; 32] (AES keys) or [u32; 8] (large integers)
// to be safely cloned when used as secrets.
#[cfg(feature = "zeroize")]
impl<T: CloneableSecretMarker, const N: usize> CloneableSecretMarker for [T; N] {}
