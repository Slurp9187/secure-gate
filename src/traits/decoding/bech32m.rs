//! Bech32m decoding trait.
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum)
//! to byte vectors, with optional HRP validation. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32m` feature** (distinct from classic Bech32).
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate Bech32m strings upstream before wrapping
//!   in secrets. HRP validation prevents cross-protocol confusion attacks.
//! - **HRP validation**: use `try_from_bech32m_expect_hrp` to enforce expected HRPs;
//!   test empty and invalid HRP inputs in security-critical code.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//! - **BIP-350 checksum**: Enhanced error detection over BIP-173 Bech32.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::FromBech32mStr;
//! # #[cfg(feature = "encoding-bech32m")]
//! # {
//!
//! // BIP-350 minimal valid Bech32m test vector
//! let bech32m = "A1LQFN3A";
//!
//! let (hrp, data) = bech32m.try_from_bech32m().expect("valid bech32m");
//! assert_eq!(hrp.to_ascii_lowercase(), "a");
//! assert!(data.is_empty());
//!
//! // HRP validation — prevents cross-protocol confusion
//! let data = bech32m.try_from_bech32m_expect_hrp("A").expect("HRP matches");
//! assert!(data.is_empty());
//!
//! // Error on invalid input
//! assert!("not-bech32m".try_from_bech32m().is_err());
//! # }
//! ```
#[cfg(feature = "encoding-bech32m")]
use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
#[cfg(feature = "encoding-bech32m")]
use crate::error::Bech32Error;

/// Extension trait for decoding Bech32m (BIP-350) strings into byte vectors.
///
/// *Requires feature `encoding-bech32m`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// HRP validation prevents injection attacks and cross-protocol confusion.
///
/// **Payload size limit**: Bech32m uses the standard 90-byte limit. Encoded strings
/// produced by [`ToBech32`](crate::ToBech32) (which uses the extended `Bech32Large`
/// variant, ~3.2 KB) **cannot** be decoded by this trait. Use
/// [`FromBech32Str`](crate::FromBech32Str) for large-payload round-trips.
#[cfg(feature = "encoding-bech32m")]
pub trait FromBech32mStr {
    /// Decodes a Bech32m (BIP-350) string into `(HRP, data_bytes)`.
    ///
    /// Validates the BIP-350 checksum.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::OperationFailed`] — invalid checksum or malformed string.
    /// - [`Bech32Error::ConversionFailed`] — bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBech32mStr;
    ///
    /// // BIP-350 minimal valid test vector
    /// let (hrp, data) = "A1LQFN3A".try_from_bech32m()?;
    /// assert_eq!(hrp.to_ascii_lowercase(), "a");
    /// assert!(data.is_empty());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Decodes a Bech32m (BIP-350) string, validating that the HRP matches `expected_hrp`.
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
    /// use secure_gate::FromBech32mStr;
    ///
    /// // BIP-350 minimal valid test vector
    /// let data = "A1LQFN3A".try_from_bech32m_expect_hrp("A")?;
    /// assert!(data.is_empty());
    ///
    /// // HRP mismatch returns an error
    /// assert!("A1LQFN3A".try_from_bech32m_expect_hrp("bc").is_err());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32m_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32m")]
impl<T: AsRef<str> + ?Sized> FromBech32mStr for T {
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        // Use CheckedHrpstring to validate Bech32m checksum (no-alloc)
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Bech32Error::OperationFailed)?;

        // Get HRP (lowercase)
        let hrp = checked.hrp().to_string();

        // Collect data as 8-bit bytes (handles empty)
        let data: Vec<u8> = checked.byte_iter().collect();

        Ok((hrp, data))
    }

    fn try_from_bech32m_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let (got_hrp, data) = self.try_from_bech32m()?;
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
