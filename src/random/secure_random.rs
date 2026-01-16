//! Marker trait for secure random values.
//!
//! This trait marks types containing cryptographically fresh random bytes,
//! ensuring they were generated via secure RNG and provide byte-slice access.

use crate::traits::expose_secret::ExposeSecret;

/// Marker trait for cryptographically secure random values.
///
/// Extends [] with `Inner = [u8]`, guaranteeing fresh random bytes
/// with metadata access but no mutation.
///
/// Use for generics requiring RNG-sourced data:
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::SecureRandom;
///
/// fn derive_key<R: SecureRandom>(r: &R) {
///     let bytes = r.expose_secret();  // Guaranteed fresh &[u8]
///     // Derive safely...
/// }
/// # }
/// ```
#[cfg(feature = "rand")]
pub trait SecureRandom: ExposeSecret<Inner = [u8]> {}

#[cfg(feature = "rand")]
impl<const N: usize> SecureRandom for super::FixedRandom<N> {}

#[cfg(feature = "rand")]
impl SecureRandom for super::DynamicRandom {}
