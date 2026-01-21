//! Internal macros for validated bech32 string wrapping in secure-gate types.
//!
//! This module contains macros used to implement validated from_bech32 methods
//! for Dynamic<String> types without code duplication.

/// Macro to implement validated from_bech32 for Dynamic string wrappers.
///
/// This generates a from_bech32 method that validates a bech32 string and wraps it as Dynamic<String>.
/// Performs the same checks as Bech32String::new but returns Dynamic<String> instead of Bech32String.
/// Requires the "encoding-bech32" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_bech32_validated {
    ($type:ty) => {
        /// Validate bech32 string and wrap as Dynamic<String> (panics on invalid).
        #[cfg(feature = "encoding-bech32")]
        impl $type {
            pub fn from_bech32(s: &str) -> Self {
                use bech32::primitives::decode::UncheckedHrpstring;
                // Validate like Bech32String::new
                let unchecked = UncheckedHrpstring::new(s).expect("invalid bech32 string");
                if unchecked.validate_checksum::<bech32::Bech32>().is_ok()
                    || unchecked.validate_checksum::<bech32::Bech32m>().is_ok()
                {
                    // Valid, normalize to lowercase
                    let mut normalized = s.to_string();
                    normalized.make_ascii_lowercase();
                    Self::from(normalized)
                } else {
                    panic!("invalid bech32 string");
                }
            }
        }
    };
}
