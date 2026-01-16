#[cfg(feature = "rand")]
use super::expose_secret::ExposeSecret;

/// # Secure Random Traits
///
/// This module provides traits for secure random value generation.
/// It ensures random bytes are accessible with metadata but remain immutable.
///
/// ## Key Traits
///
/// - [`SecureRandom`]: Marker trait for cryptographically secure random values
///
/// ## Security Model
///
/// - **Read-only exposure**: Only allows access to random bytes, not mutation
/// - **Metadata access**: Safe length and emptiness queries
/// - **Fresh generation**: All values come from cryptographically secure RNG
/// - **Type safety**: Polymorphic operations preserve RNG guarantees
///
use crate::random::{DynamicRandom, FixedRandom};

/// Marker trait for secure random values.
///
/// Extends [`ExposeSecret`] with `Inner = [u8]`, ensuring random bytes
/// are accessible with metadata but immutable.
/// Import this for random-specific guarantees.
#[cfg(feature = "rand")]
pub trait SecureRandom: ExposeSecret<Inner = [u8]> {}

/// Implementation for [`FixedRandom<N>`] - fixed-size secure random values.
///
/// This implementation provides the [`SecureRandom`] interface for
/// fixed-size random byte arrays generated from cryptographically secure sources.
#[cfg(feature = "rand")]
impl<const N: usize> SecureRandom for FixedRandom<N> {}

/// Implementation for [`DynamicRandom`] - dynamic-size secure random values.
///
/// This implementation provides the [`SecureRandom`] interface for
/// dynamically-sized random byte vectors generated from cryptographically secure sources.
#[cfg(feature = "rand")]
impl SecureRandom for DynamicRandom {}
