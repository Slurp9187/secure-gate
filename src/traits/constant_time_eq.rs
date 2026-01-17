//! Constant-time equality comparison for cryptographic secrets (gated behind `ct-eq`).
//!
//! This module provides the ConstantTimeEq trait, which performs equality
//! comparisons in constant time to prevent timing attacks. Regular equality
//! operations can take different amounts of time depending on the data,
//! potentially leaking information about secret values.
//!
//! Uses the `subtle` crate for secure, constant-time implementations.
//!
//! # Security Warning
//!
//! Always use `ct_eq()` instead of `==` when comparing cryptographic secrets,
//! authentication tokens, or other sensitive data that should not leak through
//! timing differences.

/// Trait for constant-time equality comparison to prevent timing attacks.
///
/// This trait provides equality comparison that takes the same amount of time
/// regardless of the input values, preventing attackers from using timing
/// differences to learn about secret data.
///
/// Implemented for byte slices and fixed-size byte arrays.
/// Uses the `subtle` crate's secure constant-time comparison.
///
/// # Security
///
/// Regular `==` comparison can short-circuit early when bytes differ,
/// creating timing differences that leak information. This trait ensures
/// all comparisons take constant time.
///
/// # Examples
///
/// Basic usage:
/// ```rust
/// # #[cfg(feature = "ct-eq")]
/// # {
/// fn main() {
/// use subtle::ConstantTimeEq;
/// let a = [1u8, 2u8, 3u8].as_slice();
/// let b = [1u8, 2u8, 3u8].as_slice();
/// let c = [1u8, 5u8, 3u8].as_slice();
///
/// assert!(bool::from(a.ct_eq(&b)));  // true
/// assert!(bool::from(!a.ct_eq(&c))); // false, but takes same time as true case
/// }
/// # }
/// ```
pub trait ConstantTimeEq {
    /// Compare two values in constant time.
    ///
    /// Returns `true` if they are equal, `false` otherwise.
    /// Safe against timing attacks.
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for byte slices.
impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for fixed-size byte arrays.
impl<const N: usize> ConstantTimeEq for [u8; N] {
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice())
    }
}
