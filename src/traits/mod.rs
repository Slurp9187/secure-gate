/// # Traits for Polymorphic Secret Handling
///
/// This module provides the fundamental traits for working with secrets in a polymorphic,
/// zero-cost way. These traits enable generic code that can operate on different secret
/// wrapper types while maintaining strong security guarantees.
///
/// ## Traits Overview
///
/// - [`ExposeSecret`] - Read-only secret access with metadata
/// - [`ExposeSecretMut`] - Mutable secret access
/// - [`SecureRandom`] - Marker for cryptographically secure random values (requires `rand` feature)
///
/// ## Security Guarantees
///
/// - **Read-only enforcement**: Random and encoding wrappers only expose read-only access
/// - **Controlled mutability**: Core wrappers provide full access while others remain read-only
/// - **Zero-cost abstractions**: All traits use `#[inline(always)]` for optimal performance
/// - **Type safety**: Polymorphic operations preserve secret wrapper invariants
///
/// ## Feature Gates
///
/// Some traits require optional Cargo features:
/// - `rand`: Enables [`SecureRandom`] and random wrapper implementations
// Secret Exposure Traits
pub mod expose_secret;
pub mod expose_secret_mut;
pub use expose_secret::ExposeSecret;
pub use expose_secret_mut::ExposeSecretMut;

// Random Generation Traits (requires `rand` feature)
#[cfg(feature = "rand")]
pub use crate::random::SecureRandom; // ← Cross-module re-export
