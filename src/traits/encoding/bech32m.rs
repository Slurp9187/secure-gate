//! Bech32m encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to Bech32m strings
//! (BIP-350 checksum) with a specified HRP. Designed for intentional export.
//!
//! Requires the `encoding-bech32m` feature.
//!
//! # Security Notes
//! - **BIP-350 variant**: Enhanced checksum for better error detection.
//! - **Full secret exposure**: Use only after explicit `.expose_secret()`.
//! - **HRP validation**: `try_to_bech32m` allows optional expected-HRP check.
//! - **Scoped access enforced**: No implicit exposure paths.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32m")]
//! use secure_gate::{Fixed, ToBech32m, ExposeSecret};
//!
//! # #[cfg(feature = "encoding-bech32m")]
//! {
//! let secret = Fixed::new([0u8]);
//! let bech32m = secret.with_secret(|s| s.to_bech32m("A"));
//! assert!(bech32m.starts_with("a1"));
//! // bech32m is a BIP-350 encoded string starting with "a1" (prefix "A" + separator)
//! # }
//! ```
#[cfg(feature = "encoding-bech32m")]
use bech32::{encode_lower, Bech32m, Hrp};

#[cfg(feature = "encoding-bech32m")]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data to Bech32m strings with a specified HRP.
///
/// Requires `encoding-bech32m` feature.
///
/// All methods require explicit `.expose_secret()` access first.
#[cfg(feature = "encoding-bech32m")]
pub trait ToBech32m {
    /// Encode bytes as Bech32m with the specified HRP (infallible version).
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String;

    /// Fallibly encode bytes as Bech32m with the specified HRP and optional expected-HRP validation.
    fn try_to_bech32m(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-bech32m")]
impl<T: AsRef<[u8]> + ?Sized> ToBech32m for T {
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        let hrp_parsed = Hrp::parse(hrp).expect("invalid hrp");
        encode_lower::<Bech32m>(hrp_parsed, self.as_ref()).expect("bech32m encoding failed")
    }

    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error> {
        let hrp_parsed = Hrp::parse(hrp).map_err(|_| Bech32Error::InvalidHrp)?;
        if let Some(exp) = expected_hrp {
            if hrp != exp {
                #[cfg(debug_assertions)]
                return Err(Bech32Error::UnexpectedHrp {
                    expected: exp.to_string(),
                    got: hrp.to_string(),
                });
                #[cfg(not(debug_assertions))]
                return Err(Bech32Error::UnexpectedHrp);
            }
        }
        encode_lower::<Bech32m>(hrp_parsed, self.as_ref()).map_err(|_| Bech32Error::OperationFailed)
    }
}

#[cfg(feature = "encoding-bech32m")]
#[cfg(test)]
mod tests {
    use bech32::{encode_lower, Bech32m, Hrp};

    #[test]
    #[should_panic(expected = "TooLong")]
    fn test_capped_overflow_bech32m() {
        let large_data = vec![0u8; 800];
        let hrp = Hrp::parse("test").unwrap();
        let _ = encode_lower::<Bech32m>(hrp, &large_data).unwrap();
    }
}
