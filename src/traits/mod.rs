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
/// - [`CloneSafe`] - Opt-in safe cloning with zeroization (requires `zeroize` feature)
/// - [`ConstantTimeEq`] - Constant-time equality to prevent timing attacks (requires `ct-eq` feature)
/// - [`SecureEncoding`] - Extension trait for secure byte encoding to strings (requires encoding features)
/// - [`SerializableSecret`] - Marker for types allowing secure serialization (requires `serde-serialize` feature)
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
/// - `zeroize`: Enables [`CloneSafe`] for safe cloning
/// - `ct-eq`: Enables [`ConstantTimeEq`] for constant-time comparisons
/// - `encoding` (or `encoding-hex`, `encoding-base64`, `encoding-bech32`): Enables [`SecureEncoding`] for byte encoding
/// - `serde`: Enables [`SerializableSecret`] for opt-in serialization
// Secret Exposure Traits
pub mod expose_secret;
pub use expose_secret::ExposeSecret;

pub mod expose_secret_mut;
pub use expose_secret_mut::ExposeSecretMut;

pub mod secure_random;
#[cfg(feature = "rand")]
pub use secure_random::SecureRandom;

#[cfg(feature = "zeroize")]
pub mod clone_safe;
#[cfg(feature = "zeroize")]
pub use clone_safe::CloneSafe;

#[cfg(feature = "serde")]
pub mod serializable_secret;
#[cfg(feature = "serde-serialize")]
pub use serializable_secret::SerializableSecret;

pub mod constant_time_eq;
#[cfg(feature = "ct-eq")]
pub use constant_time_eq::ConstantTimeEq;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub mod secure_encoding;
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use secure_encoding::SecureEncoding;

// Random Generation Traits (requires `rand` feature)
