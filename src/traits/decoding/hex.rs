//! # FromHexStr Trait
//!
//! Extension trait for decoding hex strings to byte data.
//!
//! This trait provides secure, explicit decoding of hex strings to byte vectors.
//! Input should be treated as untrusted; use fallible methods.
//!
//! ## Security Warning
//!
//! Decoding input from untrusted sources should use fallible `try_` methods.
//! Invalid input may indicate tampering or errors.
//!

#[cfg(feature = "encoding-hex")]
use ::hex as hex_crate;

#[cfg(feature = "encoding-hex")]
use crate::error::HexError;

/// Extension trait for decoding hex strings to byte data.
///
/// Input should be treated as untrusted; use fallible methods.
///
/// # Security Warning
///
/// Decoding input from untrusted sources should use fallible `try_` methods.
/// Invalid input may indicate tampering or errors.
///
/// ## Example
///
/// ```rust
/// # #[cfg(feature = "encoding-hex")]
/// use secure_gate::FromHexStr;
/// # #[cfg(feature = "encoding-hex")]
/// let hex_string = "424344";
/// # #[cfg(feature = "encoding-hex")]
/// let bytes = hex_string.try_from_hex().unwrap();
/// // bytes is now Vec<u8>: [66, 66, 66]
/// ```
#[cfg(feature = "encoding-hex")]
pub trait FromHexStr {
    /// Fallibly decode a hex string to bytes.
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-hex")]
impl<T: AsRef<str> + ?Sized> FromHexStr for T {
    fn try_from_hex(&self) -> Result<Vec<u8>, HexError> {
        hex_crate::decode(self.as_ref()).map_err(|_| HexError::InvalidHex)
    }
}
