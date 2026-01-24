// # Traits for Polymorphic Secret Handling
//
// This module provides the fundamental traits for working with secrets in a polymorphic,
// zero-cost way. These traits enable generic code that can operate on different secret
// wrapper types while maintaining strong security guarantees.
//
// ## Traits Overview
//
// - [`ExposeSecret`] - Read-only secret access with metadata
// - [`ExposeSecretMut`] - Mutable secret access
// - [`CloneableType`] - Opt-in safe cloning with zeroization (requires cloneable feature)
// - [`ConstantTimeEq`] - Constant-time equality to prevent timing attacks (requires ct-eq feature)
// - [`SecureEncoding`] - Umbrella trait for secure byte encoding to strings (requires encoding features)
// - [`SecureDecoding`] - Umbrella trait for secure decoding from strings (requires encoding features)
// - [`SerializableType`] - Marker for types allowing secure serialization (requires serde-serialize feature)
//
// ## Security Guarantees
//
// - **Read-only enforcement**: Random and encoding wrappers only expose read-only access
// - **Controlled mutability**: Core wrappers provide full access while others remain read-only
// - **Zero-cost abstractions**: All traits use `#[inline(always)]` for optimal performance
// - **Type safety**: Polymorphic operations preserve secret wrapper invariants
//
// ## Feature Gates
//
// Some traits require optional Cargo features:
// - rand: Enables random wrapper implementations
// - cloneable: Enables [`CloneableType`] for safe cloning
// - ct-eq: Enables [`ConstantTimeEq`] for constant-time comparisons
// - encoding (or encoding-hex, encoding-base64, encoding-bech32): Enables [`SecureEncoding`] and [`SecureDecoding`] for byte encoding/decoding
// - serde-serialize: Enables [`SerializableType`] for opt-in serialization
pub mod expose_secret;
pub use expose_secret::ExposeSecret;

pub mod expose_secret_mut;
pub use expose_secret_mut::ExposeSecretMut;

#[cfg(feature = "ct-eq")]
pub mod constant_time_eq;
#[cfg(feature = "ct-eq")]
pub use constant_time_eq::ConstantTimeEq;

#[cfg(feature = "hash-eq")]
pub mod hash_eq;
#[cfg(feature = "hash-eq")]
pub use hash_eq::HashEq;

pub mod decoding;
pub mod encoding;

#[cfg(feature = "encoding-base64")]
pub use decoding::FromBase64UrlStr;
#[cfg(feature = "encoding-bech32")]
pub use decoding::FromBech32Str;
#[cfg(feature = "encoding-bech32")]
pub use decoding::FromBech32mStr;
#[cfg(feature = "encoding-hex")]
pub use decoding::FromHexStr;

#[cfg(feature = "encoding-base64")]
pub use encoding::ToBase64Url;
#[cfg(feature = "encoding-bech32")]
pub use encoding::ToBech32;
#[cfg(feature = "encoding-bech32")]
pub use encoding::ToBech32m;
#[cfg(feature = "encoding-hex")]
pub use encoding::ToHex;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub trait SecureEncoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<T: AsRef<[u8]> + ?Sized> SecureEncoding for T {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub trait SecureDecoding {}

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<T: AsRef<str> + ?Sized> SecureDecoding for T {}

#[cfg(feature = "cloneable")]
pub mod cloneable_type;
#[cfg(feature = "cloneable")]
pub use cloneable_type::CloneableType;

#[cfg(feature = "serde-serialize")]
pub mod serializable_type;
#[cfg(feature = "serde-serialize")]
pub use serializable_type::SerializableType;
