//! Internal macros for bech32 decoding in secure-gate types.
//!
//! This module contains macros used to implement from_bech32 methods
//! for Dynamic types without code duplication.

/// Macro to implement from_bech32 for Dynamic byte vectors.
///
/// This generates a from_bech32 method that decodes a bech32 string with HRP to Vec<u8>.
/// Requires the "encoding-bech32" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_bech32 {
    ($type:ty) => {
        /// Decode from bech32 string with HRP to Vec<u8> (panics on invalid/HRP mismatch).
        #[cfg(feature = "encoding-bech32")]
        impl $type {
            pub fn from_bech32(s: &str, hrp: &str) -> Self {
                use bech32::decode;
                let (decoded_hrp, decoded_data) = decode(s).expect("invalid bech32 string");
                if decoded_hrp.as_str() != hrp {
                    core::panic!(
                        "bech32 HRP mismatch: expected {}, got {}",
                        hrp,
                        decoded_hrp.as_str()
                    );
                }
                Self::from(decoded_data)
            }
        }
    };
}
