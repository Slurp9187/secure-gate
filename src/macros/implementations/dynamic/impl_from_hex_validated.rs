//! Internal macros for validated hex string wrapping in secure-gate types.
//!
//! This module contains macros used to implement validated from_hex methods
//! for Dynamic<String> types without code duplication.

/// Macro to implement validated from_hex for Dynamic string wrappers.
///
/// This generates a from_hex method that validates a hex string and wraps it as Dynamic<String>.
/// Performs the same checks as HexString::new but returns Dynamic<String> instead of HexString.
/// Requires the "encoding-hex" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_hex_validated {
    ($type:ty) => {
        /// Validate hex string and wrap as Dynamic<String> (panics on invalid).
        #[cfg(feature = "encoding-hex")]
        impl $type {
            pub fn from_hex(s: &str) -> Self {
                // Validate upfront (like HexString::new)
                if s.len() % 2 != 0 {
                    panic!("invalid hex string");
                }
                let mut bytes = s.as_bytes().to_vec();
                for b in &mut bytes {
                    match *b {
                        b'A'..=b'F' => *b += 32, // 'A' → 'a' (lowercase)
                        b'a'..=b'f' | b'0'..=b'9' => {}
                        _ => {
                            // Zeroize invalid input if zeroize feature enabled
                            #[cfg(feature = "zeroize")]
                            zeroize::Zeroize::zeroize(&mut bytes);
                            panic!("invalid hex string");
                        }
                    }
                }
                // Convert back to string after validation/normalization
                let validated_string =
                    String::from_utf8(bytes).expect("valid UTF-8 after hex normalization");
                Self::from(validated_string)
            }
        }
    };
}
