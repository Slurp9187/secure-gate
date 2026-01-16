#[cfg(feature = "rand")]
use super::expose_secret::ExposeSecret;
#[cfg(feature = "rand")]
use super::secure_metadata::SecureMetadata;

/// # Secure Random Traits
///
/// This module provides traits that combine random generation capabilities
/// with metadata queries for cryptographic random values. It enables polymorphic
/// operations on different random wrapper types while maintaining security.
///
/// ## Key Traits
///
/// - [`SecureRandom`]: Combines random exposure with metadata access
///
/// ## Security Model
///
/// - **Read-only exposure**: Only allows access to random bytes, not mutation
/// - **Metadata access**: Safe length and emptiness queries
/// - **Fresh generation**: All values come from cryptographically secure RNG
/// - **Type safety**: Polymorphic operations preserve RNG guarantees
///
/// ## Usage
///
/// ```
/// # #[cfg(feature = "rand")]
/// # {
/// use secure_gate::random::{DynamicRandom, FixedRandom};
/// use secure_gate::SecureRandom;
///
/// // Fixed-size random values
/// let fixed: FixedRandom<32> = FixedRandom::generate();
/// assert_eq!(fixed.len(), 32);
/// let bytes = fixed.expose_secret(); // &[u8] access
///
/// // Dynamic-size random values
/// let dynamic = DynamicRandom::generate(64);
/// assert_eq!(dynamic.len(), 64);
/// let bytes = dynamic.expose_secret(); // &[u8] access
/// # }
/// ```
use crate::random::{DynamicRandom, FixedRandom};

/// Random value generation with metadata access.
///
/// This trait combines [`ExposeSecret`] and [`SecureMetadata`] to provide
/// a complete interface for working with cryptographically secure random values.
/// All implementations guarantee that the underlying values were generated from
/// a secure entropy source and remain immutable after generation.
///
/// ## Type Constraints
///
/// - `Inner = [u8]`: Random values are always byte sequences
/// - Implements `ExposeSecret`: Read-only access only (no mutation)
/// - Implements `SecureMetadata`: Length queries without exposure
///
/// ## Security
///
/// - Values cannot be modified after generation
/// - Fresh entropy from OS RNG or cryptographically secure sources
/// - Polymorphic operations maintain RNG security properties
#[cfg(feature = "rand")]
pub trait SecureRandom: ExposeSecret<Inner = [u8]> + SecureMetadata {}

/// Implementation for [`FixedRandom<N>`] - fixed-size secure random values.
///
/// Implementation for [`FixedRandom<N>`] - fixed-size secure random values.
///
/// This implementation provides the complete [`SecureRandom`] interface for
/// fixed-size random byte arrays generated from cryptographically secure sources.
#[cfg(feature = "rand")]
impl<const N: usize> SecureRandom for FixedRandom<N> {}

/// Implementation for [`DynamicRandom`] - dynamic-size secure random values.
///
/// This implementation provides the complete [`SecureRandom`] interface for
/// dynamically-sized random byte vectors generated from cryptographically secure sources.
#[cfg(feature = "rand")]
impl SecureRandom for DynamicRandom {}
