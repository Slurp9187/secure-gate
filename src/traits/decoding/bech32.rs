//! Bech32 decoding trait.
//!
//! This trait provides secure, explicit decoding of Bech32 strings (BIP-173 checksum)
//! to byte vectors, with optional HRP validation. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! Requires the `encoding-bech32` feature.
//!
//! # Security Notes
//! - **Untrusted input**: Always treat decoded data as potentially malicious.
//!   Use fallible methods and validate lengths/content after decoding.
//! - **Invalid input**: May indicate tampering, injection attempts, or errors —
//!   log/handle carefully without leaking details.
//! - **HRP validation**: Use `try_from_bech32_expect_hrp` to enforce expected HRPs
//!   and prevent cross-protocol confusion attacks.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in `Fixed` or `Dynamic` for secrets.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32")]
//! use secure_gate::FromBech32Str;
//!
//! # #[cfg(feature = "encoding-bech32")]
//! {
//! let bech32 = "test1qq2htfgz";
//! let (hrp, bytes) = bech32.try_from_bech32().unwrap();
//! assert_eq!(hrp, "test");
//! assert_eq!(bytes, vec![0u8]);
//!
//! // Expect specific HRP
//! let data = bech32.try_from_bech32_expect_hrp("test").unwrap();
//! assert_eq!(data, vec![0u8]);
//! # }
//! ```
#[cfg(feature = "encoding-bech32")]
use super::super::helpers::bech32::{encode_lower, Bech32Large, Fe32, Fe32IterExt, Hrp};

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Extension trait for decoding Bech32 strings to byte data.
///
/// Requires `encoding-bech32` feature.
///
/// # Security Warning
///
/// Treat all input as untrusted — invalid Bech32 may indicate tampering.
/// Always use the fallible `try_from_bech32` / `try_from_bech32_expect_hrp`
/// and handle errors securely.
#[cfg(feature = "encoding-bech32")]
pub trait FromBech32Str {
    /// Fallibly decodes a Bech32 string to (HRP, bytes).
    ///
    /// Validates checksum and returns the human-readable part and data.
    /// Requires `encoding-bech32` feature.
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Fallibly decodes a Bech32 string, expecting the specified HRP, returning bytes.
    ///
    /// Validates checksum and HRP match; returns [`Bech32Error::UnexpectedHrp`] if HRP mismatch.
    /// Requires `encoding-bech32` feature.
    fn try_from_bech32_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<str> + ?Sized> FromBech32Str for T {
    fn try_from_bech32(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        if let Some(pos) = s.rfind('1') {
            let hrp_str = &s[..pos];
            let data_str = &s[pos + 1..];
            let hrp = Hrp::parse(hrp_str).map_err(|_| Bech32Error::InvalidHrp)?;
            // For Bech32Large, checksum is 6 chars
            if data_str.len() < 6 {
                return Err(Bech32Error::OperationFailed);
            }
            let data_part = &data_str[..data_str.len() - 6];
            let mut fe32s = Vec::new();
            for c in data_part.chars() {
                let fe = Fe32::from_char(c).map_err(|_| Bech32Error::OperationFailed)?;
                fe32s.push(fe);
            }
            let data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();
            // Validate by re-encoding with Bech32Large
            let re_encoded = encode_lower::<Bech32Large>(hrp, &data)
                .map_err(|_| Bech32Error::OperationFailed)?;
            if re_encoded != s {
                return Err(Bech32Error::OperationFailed);
            }
            if data.is_empty() {
                return Err(Bech32Error::OperationFailed);
            }
            Ok((hrp.to_string(), data))
        } else {
            Err(Bech32Error::OperationFailed)
        }
    }

    fn try_from_bech32_expect_hrp(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let (hrp, data) = self.try_from_bech32()?;
        if !hrp.to_string().eq_ignore_ascii_case(expected_hrp) {
            #[cfg(debug_assertions)]
            return Err(Bech32Error::UnexpectedHrp {
                expected: expected_hrp.to_string(),
                got: hrp.to_string(),
            });
            #[cfg(not(debug_assertions))]
            return Err(Bech32Error::UnexpectedHrp);
        }
        Ok(data)
    }
}
