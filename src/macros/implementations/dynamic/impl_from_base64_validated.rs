//! Internal macros for validated base64 string wrapping in secure-gate types.
//!
//! This module contains macros used to implement validated from_base64 methods
//! for Dynamic<String> types without code duplication.

/// Macro to implement validated from_base64 for Dynamic string wrappers.
///
/// This generates a from_base64 method that validates a base64 string and wraps it as Dynamic<String>.
/// Performs the same checks as Base64String::new but returns Dynamic<String> instead of Base64String.
/// Requires the "encoding-base64" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_base64_validated {
    ($type:ty) => {
        /// Validate base64 string and wrap as Dynamic<String> (panics on invalid).
        #[cfg(feature = "encoding-base64")]
        impl $type {
            pub fn from_base64(s: &str) -> Self {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                // Validate by attempting decode (like Base64String::new)
                if URL_SAFE_NO_PAD.decode(s).is_ok() {
                    Self::from(s.to_string())
                } else {
                    panic!("invalid base64 string");
                }
            }
        }
    };
}
