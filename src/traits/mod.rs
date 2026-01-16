/// # Core Traits for Polymorphic Secret Handling
///
/// This module provides the fundamental traits for working with secrets in a polymorphic,
/// zero-cost way. These traits enable generic code that can operate on different secret
/// wrapper types while maintaining strong security guarantees.
///
/// ## Traits Overview
///
/// - [`ExposeSecret`] & [`ExposeSecretMut`] - Polymorphic secret access with controlled mutability
/// - [`SecureMetadata`] - Length and emptiness queries without exposing secrets
/// - [`SecureRandom`] - Combined random generation with metadata (requires `rand` feature)
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
/// Module containing secret exposure traits.
pub mod expose_secret;
/// Re-export exposure traits for convenient access.
pub use expose_secret::{ExposeSecret, ExposeSecretMut};
/// Module containing secret exposure extension traits.
pub mod expose_secret_ext;
/// Re-export exposure extension traits for convenient access.
pub use expose_secret_ext::{ExposeSecretExt, ExposeSecretMutExt};

// Metadata Traits
/// Module containing metadata traits.
pub mod secure_metadata;
/// Re-export metadata traits for convenient access.
pub use secure_metadata::SecureMetadata;
/// Module containing metadata extension traits.
pub mod secure_metadata_ext;
/// Re-export metadata extension traits for convenient access.
pub use secure_metadata_ext::SecureMetadataExt;

// Random Generation Traits (requires `rand` feature)
#[cfg(feature = "rand")]
/// Module containing random generation traits.
pub mod secure_random;
#[cfg(feature = "rand")]
/// Re-export random traits when the `rand` feature is enabled.
pub use secure_random::SecureRandom;
#[cfg(feature = "rand")]
/// Module containing random generation extension traits.
pub mod secure_random_ext;
#[cfg(feature = "rand")]
/// Re-export random extension traits when the `rand` feature is enabled.
pub use secure_random_ext::SecureRandomExt;
