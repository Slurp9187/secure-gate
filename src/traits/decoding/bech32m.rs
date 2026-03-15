//! Bech32m decoding trait.
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum)
//! to byte vectors, with optional HRP validation. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32m` feature** (distinct from classic Bech32).
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
//! # use secure_gate::FromBech32mStr;
//! #
//! # #[cfg(feature = "encoding-bech32m")] {
//! // Official BIP-350 minimal valid Bech32m test vector
//! let bech32m = "A1LQFN3A";
//!
//! // Basic decoding
//! let (hrp, data) = bech32m.try_from_bech32m()
//!     .expect("valid bech32m string");
//! assert_eq!(hrp.to_ascii_lowercase(), "a");
//! assert!(data.is_empty());
//!
//! // With expected HRP
//! let data = bech32m.try_from_bech32m_expect_hrp("A")
//!     .expect("HRP should match");
//! assert!(data.is_empty());
//! # }
//! ```
#[cfg(feature = "encoding-bech32m")]
use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
#[cfg(feature = "encoding-bech32m")]
use crate::error::Bech32Error;

/// Extension trait for decoding Bech32m strings to byte data.
///
/// **Requires the `encoding-bech32m` feature.**
///
/// # Security Warning
///
/// Treat all input as untrusted — invalid Bech32m may indicate tampering.
/// Always use the fallible `try_from_bech32m` / `try_from_bech32m_expect_hrp`
/// and handle errors securely.
#[cfg(feature = "encoding-bech32m")]
pub trait FromBech32mStr {
    /// Fallibly decodes a Bech32m string to (HRP, bytes).
    ///
    /// Validates BIP-350 checksum and returns the human-readable part and data.
    fn try_from_bech32m(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Fallibly decodes a Bech32m string, expecting the specified HRP, returning bytes.
    ///
    /// Validates checksum and HRP match; returns [`Bech32Error::UnexpectedHrp`] if HRP mismatch.
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
