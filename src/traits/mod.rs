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
/// - [`CloneableType`] - Opt-in safe cloning with zeroization (requires zeroize feature)
/// - [`ConstantTimeEq`] - Constant-time equality to prevent timing attacks (requires ct-eq feature)
/// - [`SecureEncoding`] - Extension trait for secure byte encoding to strings (requires encoding features)
/// - [`ExportableType`] - Marker for types allowing secure serialization (requires serde-serialize feature)
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
/// - rand: Enables random wrapper implementations
/// - zeroize: Enables [`CloneableType`] for safe cloning
/// - ct-eq: Enables [`ConstantTimeEq`] for constant-time comparisons
/// - encoding (or encoding-hex, encoding-base64, encoding-bech32): Enables [`SecureEncoding`] for byte encoding
/// - serde: Enables [`ExportableType`] for opt-in serialization
// Secret Exposure Traits
pub mod expose_secret;
pub use expose_secret::ExposeSecret;

pub mod expose_secret_mut;
pub use expose_secret_mut::ExposeSecretMut;

#[cfg(feature = "zeroize")]
pub mod cloneable_type;
#[cfg(feature = "zeroize")]
pub use cloneable_type::CloneableType;

#[cfg(feature = "serde-serialize")]
pub mod exportable_type;
#[cfg(feature = "serde-serialize")]
pub use exportable_type::ExportableType;

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
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use secure_encoding::SecureEncoding;

/// Sealed marker trait for redacted Debug output.
pub trait RedactedDebug: redacted_debug::Sealed {}

pub mod redacted_debug {
    pub trait Sealed {}
}

/// Sealed marker trait for secure construction (random/decoding).
pub trait SecureConstruction: secure_construction::Sealed {
    /// Generate a secure random instance (panics on failure).
    #[cfg(feature = "rand")]
    fn from_random() -> Self;

    /// Decode from hex string (panics on invalid/length mismatch).
    #[cfg(feature = "encoding-hex")]
    fn from_hex(s: &str) -> Self;

    /// Decode from base64 string (panics on invalid/length mismatch).
    #[cfg(feature = "encoding-base64")]
    fn from_base64(s: &str) -> Self;

    /// Decode from bech32 string with HRP (panics on invalid).
    #[cfg(feature = "encoding-bech32")]
    fn from_bech32(s: &str, hrp: &str) -> Self;
}

pub mod secure_construction {
    pub trait Sealed {}
}

/// Sealed marker trait for on-demand hash-based equality.
#[cfg(feature = "hash-eq")]
pub trait HashEqSecret: hash_eq_secret::Sealed {
    fn hash_digest(&self) -> [u8; 32];
}

#[cfg(feature = "hash-eq")]
pub mod hash_eq_secret {
    pub trait Sealed {}
}
