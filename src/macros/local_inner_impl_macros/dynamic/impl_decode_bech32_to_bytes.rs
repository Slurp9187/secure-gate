//! Internal macros for bech32 decoding in secure-gate types.
//!
//! This module contains macros used to implement decode_bech32_to_bytes methods
//! for Dynamic<String> types without code duplication.

/// Macro to implement bech32 decoding methods for Dynamic string wrappers.
///
/// This generates decode_bech32_to_bytes and decode_bech32_into_bytes methods.
/// Requires the "encoding-bech32" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_decode_bech32_to_bytes {
    () => {
        #[cfg(feature = "encoding-bech32")]
        impl $crate::Dynamic<String> {
            /// Decode the string as bech32 to bytes, ignoring HRP (assumes validated bech32 string).
            pub fn decode_bech32_to_bytes(&self) -> Vec<u8> {
                use bech32::decode;
                let (_, data) = decode(self.expose_secret().as_str())
                    .expect("validated bech32 string should decode");
                data
            }

            /// Consuming version: decode as bech32 and immediately drop the wrapper.
            pub fn decode_bech32_into_bytes(self) -> Vec<u8> {
                use bech32::decode;
                let (_, data) = decode(self.expose_secret().as_str())
                    .expect("validated bech32 string should decode");
                data
            }

            /// Decode the string as bech32 to bytes, checking that the HRP matches the expected one.
            pub fn decode_bech32_to_bytes_with_hrp(
                &self,
                expected_hrp: &str,
            ) -> Result<Vec<u8>, $crate::error::Bech32EncodingError> {
                use bech32::decode;
                let (decoded_hrp, data) = decode(self.expose_secret().as_str())
                    .map_err(|_| $crate::error::Bech32EncodingError::EncodingFailed)?;
                if decoded_hrp.as_str() != expected_hrp {
                    return Err($crate::error::Bech32EncodingError::InvalidHrp);
                }
                Ok(data)
            }

            /// Consuming version: decode as bech32 with HRP check and immediately drop the wrapper.
            pub fn decode_bech32_into_bytes_with_hrp(
                self,
                expected_hrp: &str,
            ) -> Result<Vec<u8>, $crate::error::Bech32EncodingError> {
                use bech32::decode;
                let (decoded_hrp, data) = decode(self.expose_secret().as_str())
                    .map_err(|_| $crate::error::Bech32EncodingError::EncodingFailed)?;
                if decoded_hrp.as_str() != expected_hrp {
                    return Err($crate::error::Bech32EncodingError::InvalidHrp);
                }
                Ok(data)
            }
        }
    };
}
