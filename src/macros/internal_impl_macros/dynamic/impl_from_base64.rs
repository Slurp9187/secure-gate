//! Internal macros for base64 decoding in secure-gate types.
//!
//! This module contains macros used to implement from_base64 methods
//! for Dynamic types without code duplication.

/// Macro to implement from_base64 for Dynamic byte vectors.
///
/// This generates a from_base64 method that decodes a base64 string to Vec<u8>.
/// Requires the "encoding-base64" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_base64 {
    ($type:ty) => {
        /// Decode from base64 string to Vec<u8> (panics on invalid).
        #[cfg(feature = "encoding-base64")]
        impl $type {
            pub fn from_base64(s: &str) -> Self {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                let decoded = URL_SAFE_NO_PAD.decode(s).expect("invalid base64 string");
                Self::from(decoded)
            }
        }
    };
}
