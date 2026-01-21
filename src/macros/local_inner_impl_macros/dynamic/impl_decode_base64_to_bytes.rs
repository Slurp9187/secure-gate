//! Internal macros for base64 decoding in secure-gate types.
//!
//! This module contains macros used to implement decode_base64_to_bytes methods
//! for `Dynamic<String>` types without code duplication.

/// Macro to implement base64 decoding methods for Dynamic string wrappers.
///
/// This generates decode_base64_to_bytes and decode_base64_into_bytes methods.
/// Requires the "encoding-base64" feature.
#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_decode_base64_to_bytes {
    () => {
        #[cfg(feature = "encoding-base64")]
        impl $crate::Dynamic<String> {
            /// Decode the string as base64 to bytes (assumes validated base64 string).
            pub fn decode_base64_to_bytes(&self) -> Vec<u8> {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                URL_SAFE_NO_PAD
                    .decode(self.expose_secret())
                    .expect("validated base64 string should decode")
            }

            /// Consuming version: decode as base64 and immediately drop the wrapper.
            pub fn decode_base64_into_bytes(self) -> Vec<u8> {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                URL_SAFE_NO_PAD
                    .decode(self.expose_secret())
                    .expect("validated base64 string should decode")
            }
        }
    };
}
