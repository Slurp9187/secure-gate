//! Marker trait and implementations for types that can be safely cloned as secrets.
//!
//! This module defines the [`CloneSafe`] trait and provides blanket
//! implementations for primitive types and fixed-size arrays that are safe to clone
//! when handling sensitive data. The trait ensures that only types meeting the
//! security requirements (Clone + Zeroize) can be used in cloneable secret wrappers.

/// Marker trait enabling safe cloning of secrets.
///
/// **WARNING**: Implementing this trait allows deep cloning of secret data, which can
/// prolong memory lifetime and increase attack surface. Only implement for small,
/// primitive-like types (e.g., fixed arrays of primitives). Prefer built-in
/// `CloneableArray`, `CloneableString`, or `CloneableVec` for common cases.
/// Misuse can bypass the crate's no-accidental-clone guarantees.
/// Custom implementations are allowed but strongly discouraged — they can prolong secret lifetime.
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
///
/// # Examples
///
/// Implement for a custom secret type:
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::CloneSafe;
/// use zeroize::Zeroize;
///
/// #[derive(Clone)]
/// struct MySecret([u8; 32]);
///
/// impl CloneSafe for MySecret {}
///
/// impl Zeroize for MySecret {
///     fn zeroize(&mut self) {
///         zeroize::Zeroize::zeroize(&mut self.0);
///     }
/// }
///
/// let original = MySecret([1u8; 32]);
/// let copy = original.clone(); // Safe, zeroized on drop
/// # }
/// ```
pub trait CloneSafe: Clone + zeroize::Zeroize {
    // Pure marker, no methods
}

// Blanket implementations for primitive types that are safe to clone as secrets.
// These include integer types commonly used in cryptographic operations like
// keys, nonces, counters, and other small fixed-size values.
impl CloneSafe for i8 {}
impl CloneSafe for i16 {}
impl CloneSafe for i32 {}
impl CloneSafe for i64 {}
impl CloneSafe for i128 {}
impl CloneSafe for isize {}

impl CloneSafe for u8 {}
impl CloneSafe for u16 {}
impl CloneSafe for u32 {}
impl CloneSafe for u64 {}
impl CloneSafe for u128 {}
impl CloneSafe for usize {}

impl CloneSafe for bool {}
impl CloneSafe for char {}

// Blanket implementation for fixed-size arrays of cloneable secret types.
// This allows arrays like [u8; 32] (AES keys) or [u32; 8] (large integers)
// to be safely cloned when used as secrets.
impl<T: CloneSafe, const N: usize> CloneSafe for [T; N] {}
