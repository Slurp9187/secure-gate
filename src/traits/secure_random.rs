//! Marker trait for secure random values.
//!
//! This trait marks types containing cryptographically fresh random bytes,
//! ensuring they were generated via secure RNG and provide byte-slice access.

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
/// use secure_gate::SecureRandom;
///
/// fn derive_key<R: SecureRandom>(r: &R) {
///     let bytes = r.expose_secret();  // Guaranteed fresh &[u8]
///     // Derive safely...
/// }
/// # }
/// ```
#[cfg(feature = "rand")]
mod inner {
    use super::super::ExposeSecret;

    pub trait SecureRandom: ExposeSecret<Inner = [u8]> {}
}

#[cfg(feature = "rand")]
pub use inner::SecureRandom;

#[cfg(feature = "rand")]
impl<const N: usize> SecureRandom for crate::random::FixedRandom<N> {}

#[cfg(feature = "rand")]
impl SecureRandom for crate::random::DynamicRandom {}
