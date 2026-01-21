//! Internal macros for hex decoding in secure-gate types.
//!
//! This module contains macros used to implement from_hex methods
//! for Dynamic types without code duplication.

/// Macro to implement from_hex for Dynamic byte vectors.
///
/// This generates a from_hex method that decodes a hex string to Vec<u8>.
/// Requires the "encoding-hex" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_hex {
    ($type:ty) => {
        /// Decode from hex string to Vec<u8> (panics on invalid).
        #[cfg(feature = "encoding-hex")]
        impl $type {
            pub fn from_hex(s: &str) -> Self {
                use hex as hex_crate;
                let decoded = hex_crate::decode(s).expect("invalid hex string");
                Self::from(decoded)
            }

            pub fn try_from_hex(s: &str) -> Result<Self, $crate::HexError> {
                use hex as hex_crate;
                let decoded = hex_crate::decode(s).map_err(|_| $crate::HexError::InvalidHex)?;
                Ok(Self::from(decoded))
            }
        }
    };
}
