//! Constant-time equality comparison for cryptographic secrets.
//!
//! This module defines the [`ConstantTimeEq`] trait, which provides timing-attack-
//! resistant equality checks. Regular `==` operators can short-circuit on the first
//! differing byte, leaking information about secret values through execution time.
//!
//! All implementations use the `subtle` crate's constant-time primitives to ensure
//! comparisons take the same amount of time regardless of the data.
//!
//! Requires the `ct-eq` feature to be enabled.
//!
//! # Security Warning
//!
//! **Never** use `==` to compare cryptographic secrets, authentication tokens,
//! MACs, signatures, or other sensitive data. Always use `.ct_eq()` or the
//! recommended `ct_eq_auto()` (from `ConstantTimeEqExt`) instead.
//!
//! # When to Use
//!
//! - Small, fixed-size secrets (< 256–512 bytes): `ConstantTimeEq` is fast and deterministic.
//! - Large or variable-length secrets: Prefer `ConstantTimeEqExt::ct_eq_auto()` or `.ct_eq_hash()`
//!   (requires `ct-eq-hash`) for better performance with negligible collision risk.
//!
//! # Examples
//!
//! ```rust
//! # #[cfg(feature = "ct-eq")]
//! use secure_gate::ConstantTimeEq;
//!
//! # #[cfg(feature = "ct-eq")]
//! {
//! let a = [1u8, 2, 3, 4].as_slice();
//! let b = [1u8, 2, 3, 4].as_slice();
//! let c = [1u8, 5, 3, 4].as_slice();
//!
//! assert!(a.ct_eq(&b));     // true, constant time
//! assert!(!a.ct_eq(&c));    // false, same time as true case
//!
//! // Works on fixed-size arrays too
//! let key1 = [0u8; 32];
//! let key2 = [0u8; 32];
//! assert!(key1.ct_eq(&key2));
//! # }
//! ```
//!
//! # Trait Implementations
//!
//! Blanket impls are provided for:
//!
//! - `&[u8]` / `[u8]` (byte slices)
//! - `[u8; N]` (fixed-size byte arrays)
//! - `Vec<u8>` / `String` (when `alloc` feature is enabled)
//!
//! These cover the most common secret types in cryptographic applications.
//!
//! See [`ConstantTimeEqExt`](../constant_time_eq_ext/index.html) for probabilistic
//! fast equality on large secrets (recommended default).
#[cfg(feature = "ct-eq")]
pub trait ConstantTimeEq {
    /// Performs equality comparison in constant time.
    ///
    /// Returns `true` if the values are equal, `false` otherwise.
    /// The execution time is independent of the actual data values,
    /// preventing timing side-channel attacks.
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for byte slices.
impl ConstantTimeEq for [u8] {
    /// Compares two byte slices in constant time using `subtle`.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "ct-eq")]
/// Constant-time equality for fixed-size byte arrays.
impl<const N: usize> ConstantTimeEq for [u8; N] {
    /// Delegates to slice comparison for constant-time behavior.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice())
    }
}

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
/// Constant-time equality for owned byte vectors.
impl ConstantTimeEq for alloc::vec::Vec<u8> {
    /// Compares the contents of two `Vec<u8>` in constant time.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice())
    }
}

#[cfg(all(feature = "ct-eq", feature = "alloc"))]
/// Constant-time equality for owned strings.
impl ConstantTimeEq for alloc::string::String {
    /// Compares the UTF-8 byte contents of two `String`s in constant time.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}
