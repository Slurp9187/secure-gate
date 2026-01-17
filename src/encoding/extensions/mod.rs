//! Additional functionality and convenience methods for encoding types.
//!
//! This module provides extension traits and methods that enhance the core encoding
//! functionality with features like:
//!
//! - **Secure Encoding Extensions**: Traits for encoding byte arrays to various formats
//! - **View Types**: Safe access to encoded strings with decoding capabilities
//! - **RNG Integration**: Direct encoding of random bytes to validated strings
//! - **Consuming Methods**: Methods that consume wrappers and return decoded bytes
//!
//! The extensions are designed to work seamlessly with the main encoding types
//! while maintaining security guarantees.

#[cfg(feature = "encoding-base64")]
pub mod base64;
#[cfg(feature = "encoding-bech32")]
pub mod bech32;
#[cfg(feature = "encoding-hex")]
pub mod hex;
pub mod secure_encoding_ext;

#[cfg(feature = "encoding-bech32")]
pub use bech32::Bech32StringView;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
pub use secure_encoding_ext::SecureEncodingExt;
