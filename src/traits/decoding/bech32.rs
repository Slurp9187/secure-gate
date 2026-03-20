//! Bech32 decoding trait.
//!
//! This trait provides secure, explicit decoding of Bech32 strings (BIP-173 checksum)
//! to byte vectors, with optional HRP validation. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32` feature** (distinct from Bech32m).
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate Bech32 strings upstream before wrapping
//!   in secrets. HRP validation prevents cross-protocol confusion attacks.
//! - **HRP validation**: use `try_from_bech32_with_hrp` to enforce expected HRPs;
//!   test empty and invalid HRP inputs in security-critical code.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32")]
//! use secure_gate::FromBech32Str;
//! # #[cfg(feature = "encoding-bech32")]
//! {
//! // BIP-173 minimal valid Bech32 test vector
//! let bech32 = "A12UEL5L";
//!
//! let (hrp, data) = bech32.try_from_bech32().expect("valid bech32");
//! assert_eq!(hrp.to_ascii_lowercase(), "a");
//! assert!(data.is_empty());
//!
//! // HRP validation — prevents cross-protocol confusion
//! let data = bech32.try_from_bech32_with_hrp("A").expect("HRP matches");
//! assert!(data.is_empty());
//!
//! // Error on invalid input
//! assert!("not-bech32".try_from_bech32().is_err());
//! }
//! ```
#[cfg(feature = "encoding-bech32")]
use super::super::encoding::bech32::Bech32Large;
#[cfg(feature = "encoding-bech32")]
use bech32::primitives::decode::CheckedHrpstring;
#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Extension trait for decoding Bech32 (BIP-173) strings into byte vectors.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// HRP validation prevents injection attacks and cross-protocol confusion.
///
/// **Extended payload capacity**: Uses the custom `Bech32Large` variant (8191 Fe32
/// values, ~5 KB (5,115 bytes maximum payload)) — significantly larger than Bech32m's standard 90-byte
/// limit. Strings encoded via [`ToBech32`](crate::ToBech32) round-trip correctly here
/// but will fail with [`FromBech32mStr`](crate::FromBech32mStr) when they exceed ~90 bytes.
#[cfg(feature = "encoding-bech32")]
pub trait FromBech32Str {
    /// Decodes a Bech32 (BIP-173) string into `(HRP, data_bytes)`.
    ///
    /// Validates the BIP-173 checksum using the extended `Bech32Large`
    /// variant (8191 Fe32 limit) for large-payload compatibility.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::OperationFailed`] — invalid checksum or malformed string.
    /// - [`Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBech32Str;
    ///
    /// // BIP-173 minimal valid test vector
    /// let (hrp, data) = "A12UEL5L".try_from_bech32()?;
    /// assert_eq!(hrp.to_ascii_lowercase(), "a");
    /// assert!(data.is_empty());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Decodes a Bech32 (BIP-173) string, validating that the HRP matches `expected_hrp`.
    ///
    /// The HRP comparison is case-insensitive. Returns only the data bytes — the HRP
    /// is validated and discarded.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::OperationFailed`] — invalid checksum or malformed string.
    /// - [`Bech32Error::UnexpectedHrp`] — decoded HRP does not match `expected_hrp`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBech32Str;
    ///
    /// // BIP-173 minimal valid test vector
    /// let data = "A12UEL5L".try_from_bech32_with_hrp("A")?;
    /// assert!(data.is_empty());
    ///
    /// // HRP mismatch returns an error
    /// assert!("A12UEL5L".try_from_bech32_with_hrp("bc").is_err());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32_with_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<str> + ?Sized> FromBech32Str for T {
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        // Use CheckedHrpstring to validate Bech32 checksum (supports large via custom Bech32Large)
        let checked =
            CheckedHrpstring::new::<Bech32Large>(s).map_err(|_| Bech32Error::OperationFailed)?;

        // Get HRP (lowercase)
        let hrp = checked.hrp().to_string();

        // Collect data as 8-bit bytes (handles empty)
        let data: Vec<u8> = checked.byte_iter().collect();

        Ok((hrp, data))
    }

    fn try_from_bech32_with_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let (got_hrp, data) = self.try_from_bech32()?;
        if !got_hrp.eq_ignore_ascii_case(expected_hrp) {
            #[cfg(debug_assertions)]
            return Err(Bech32Error::UnexpectedHrp {
                expected: expected_hrp.to_string(),
                got: got_hrp,
            });
            #[cfg(not(debug_assertions))]
            return Err(Bech32Error::UnexpectedHrp);
        }
        Ok(data)
    }
}
