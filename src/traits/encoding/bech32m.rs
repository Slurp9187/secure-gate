//! Bech32m encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to Bech32m strings
//! (BIP-350 checksum) with a specified HRP. Designed for intentional export.
//!
//! Requires the `encoding-bech32m` feature.
//!
//! # Security Notes
//!
//! - **BIP-350 variant**: Enhanced checksum vs. BIP-173 Bech32 — use Bech32m
//!   for Taproot, SegWit v1+, and modern address formats.
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive.
//! - **HRP validation prevents injection attacks**: use `try_to_bech32m` with an
//!   expected HRP to enforce protocol separation; test empty and invalid HRP inputs.
//! - **Payload size capped at 90 bytes**: standard Bech32m checksum `CODE_LENGTH`
//!   limit. For larger secrets use [`ToBech32`](crate::ToBech32) with `Bech32Large`.
//! - **Treat all input as untrusted**: validate data upstream before wrapping.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{Fixed, ToBech32m, ExposeSecret};
//!
//! let secret = Fixed::new([0x00u8, 0x01]);
//!
//! // Blanket impl on the inner byte array (via with_secret):
//! let encoded = secret.with_secret(|s| s.to_bech32m("key"));
//! assert!(encoded.starts_with("key1"));
//!
//! // Wrapper method (Direct Fixed<[u8; N]> API — same result):
//! assert!(secret.to_bech32m("key").starts_with("key1"));
//! ```
#[cfg(feature = "encoding-bech32m")]
use bech32::{encode_lower, Bech32m, Hrp};

#[cfg(feature = "encoding-bech32m")]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data as Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32m`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types. Prefer [`try_to_bech32m`](Self::try_to_bech32m)
/// over the infallible [`to_bech32m`](Self::to_bech32m) — it validates the HRP and
/// prevents cross-protocol confusion attacks. HRP validation prevents injection attacks;
/// test empty and invalid HRP inputs in security-critical code.
#[cfg(feature = "encoding-bech32m")]
pub trait ToBech32m {
    /// Encodes bytes as a Bech32m (BIP-350) string with the given HRP.
    ///
    /// Panics if `hrp` is invalid or the data exceeds the standard ~90-byte limit.
    /// Prefer [`try_to_bech32m`](Self::try_to_bech32m) for any untrusted HRP.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::ToBech32m;
    ///
    /// let encoded = b"hello".to_bech32m("key");
    /// assert!(encoded.starts_with("key1"));
    /// ```
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String;

    /// Fallibly encodes bytes as a Bech32m (BIP-350) string with optional HRP validation.
    ///
    /// Pass `expected_hrp: Some("hrp")` to enforce that the encoded HRP matches;
    /// useful for round-trip validation and preventing cross-protocol confusion.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::InvalidHrp`] — `hrp` contains invalid characters.
    /// - [`Bech32Error::UnexpectedHrp`] — `expected_hrp` is `Some` and does not match `hrp`.
    /// - [`Bech32Error::OperationFailed`] — encoding failure (e.g., data too large).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::ToBech32m;
    ///
    /// let encoded = b"hello".try_to_bech32m("key", None)?;
    /// assert!(encoded.starts_with("key1"));
    ///
    /// // HRP validation
    /// assert!(b"hello".try_to_bech32m("key", Some("key")).is_ok());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
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
