//! Bech32m decoding trait.
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum)
//! to byte vectors, with optional HRP validation. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! Requires the `encoding-bech32` or `encoding-bech32m` feature.
//!
//! # Security Notes
//! - **Untrusted input**: Always treat decoded data as potentially malicious.
//!   Use fallible methods and validate lengths/content after decoding.
//! - **Invalid input**: May indicate tampering, injection attempts, or errors —
//!   log/handle carefully without leaking details.
//! - **HRP validation**: Use `try_from_bech32m_expect_hrp` to enforce expected HRPs
//!   and prevent cross-protocol confusion attacks.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in `Fixed` or `Dynamic` for secrets.
//! - **BIP-350 checksum**: Enhanced error detection over BIP-173.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
//! use secure_gate::FromBech32mStr;
//!
//! # #[cfg(any(feature = "encoding-bech32", feature = "encoding-bech32m"))]
//! {
//! let bech32m = "test1qqltm9dq";
//! let (hrp, bytes) = bech32m.try_from_bech32m().unwrap();
//! assert_eq!(hrp, "test");
//! assert_eq!(bytes, vec![0u8]);
//!
//! // Expect specific HRP
//! let data = bech32m.try_from_bech32m_expect_hrp("test").unwrap();
//! assert_eq!(data, vec![0u8]);
//! # }
//! ```
#[cfg(feature = "encoding-bech32")]
use super::super::helpers::bech32::{decode, encode_lower, Bech32m};

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Extension trait for decoding Bech32m strings to byte data.
///
/// Requires `encoding-bech32` or `encoding-bech32m` feature.
///
/// # Security Warning
///
/// Treat all input as untrusted — invalid Bech32m may indicate tampering.
/// Always use the fallible `try_from_bech32m` / `try_from_bech32m_expect_hrp`
/// and handle errors securely.
#[cfg(feature = "encoding-bech32")]
pub trait FromBech32mStr {
    /// Fallibly decodes a Bech32m string to (HRP, bytes).
    ///
    /// Validates BIP-350 checksum and returns the human-readable part and data.
    /// Requires `encoding-bech32` feature.
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Fallibly decodes a Bech32m string, expecting the specified HRP, returning bytes.
    ///
    /// Validates checksum and HRP match; returns [`Bech32Error::UnexpectedHrp`] if HRP mismatch.
    /// Requires `encoding-bech32` feature.
    fn try_from_bech32m_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<str> + ?Sized> FromBech32mStr for T {
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        // Capped + checksum validate
        let (hrp, data) = decode(self.as_ref()).map_err(|_| Bech32Error::OperationFailed)?;
        // Validate that it is Bech32m variant by re-encoding
        let re_encoded =
            encode_lower::<Bech32m>(hrp, &data).map_err(|_| Bech32Error::OperationFailed)?;
        if re_encoded != self.as_ref() {
            return Err(Bech32Error::OperationFailed);
        }
        if data.is_empty() {
            return Err(Bech32Error::OperationFailed);
        }
        Ok((hrp.to_string(), data))
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
