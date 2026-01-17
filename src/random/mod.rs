// C:\Users\chadm\Projects\secure-gate\src\random\mod.rs
//! Cryptographically secure random value generation.
//!
//! Provides [`FixedRandom`] and [`DynamicRandom`] for fresh random bytes.
//! Includes the [`SecureRandom`] marker trait for polymorphism.

/// Dynamic random bytes generation.
#[cfg(feature = "rand")]
pub mod dynamic_random;

/// Fixed-size random bytes generation.
#[cfg(feature = "rand")]
pub mod fixed_random;

// Re-export for API compatibility
/// Re-export of [`DynamicRandom`].
#[cfg(feature = "rand")]
pub use dynamic_random::DynamicRandom;
/// Re-export of [`FixedRandom`].
#[cfg(feature = "rand")]
pub use fixed_random::FixedRandom;
/// Re-export of [`SecureRandom`].
#[cfg(feature = "rand")]
pub use crate::traits::secure_random::SecureRandom;
