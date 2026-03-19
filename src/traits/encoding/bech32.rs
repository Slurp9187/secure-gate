//! Bech32 encoding trait.
//!
//! This trait provides secure, explicit encoding of byte data to Bech32 strings
//! (BIP-173 checksum) with a specified Human-Readable Part (HRP). Designed for
//! intentional export (addresses, QR codes, audited logs).
//!
//! Requires the `encoding-bech32` feature.
//!
//! # Security Notes
//!
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive.
//! - **Audit visibility**: Direct wrapper calls (`key.try_to_bech32(...)`) do **not** appear in
//!   `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams or
//!   multi-step operations, prefer `with_secret(|b| b.try_to_bech32(...))` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **HRP validation prevents injection attacks**: use `try_to_bech32` with an
//!   expected HRP to enforce protocol separation; test empty and invalid HRP inputs.
//! - **Extended limit**: Uses [`Bech32Large`] (8191 Fe32 values, ~5 KB (5,115 bytes maximum payload)) instead
//!   of the 90-character standard limit — suitable for large secrets such as
//!   age-style encryption recipients, ciphertexts, and arbitrary binary payloads.
//!   For Bitcoin address formats, use [`ToBech32m`](crate::ToBech32m) (BIP-350).
//! - **Treat all input as untrusted**: validate data upstream before wrapping.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32")]
//! use secure_gate::{Fixed, ToBech32, ExposeSecret};
//! # #[cfg(feature = "encoding-bech32")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//!
//! // Use try_to_bech32 — the sole encoding API:
//! let encoded = secret.with_secret(|s| s.try_to_bech32("test", None)).unwrap();
//! assert!(encoded.starts_with("test1"));
//! }
//! ```
#[cfg(feature = "encoding-bech32")]
use bech32::{encode_lower, Hrp};

#[cfg(feature = "encoding-bech32")]
use bech32::primitives::checksum::Checksum;

/// Custom Bech32 (BIP-173) checksum variant with an extended payload capacity.
///
/// Matches classic Bech32 checksum behavior but raises the `CODE_LENGTH` limit to
/// 8191 Fe32 values (~5 KB (5,115 bytes maximum payload)), well above the standard 90-character limit.
/// Used by the [`ToBech32`] trait to support large secrets while preserving full
/// checksum validation.
///
/// Most users interact with this type indirectly via [`ToBech32`]. It is `pub`
/// for use in `impl Checksum` and for advanced callers who construct their own
/// `encode_lower::<Bech32Large>(...)` calls.
#[cfg(feature = "encoding-bech32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32Large {}

#[cfg(feature = "encoding-bech32")]
impl Checksum for Bech32Large {
    type MidstateRepr = u32;

    const CODE_LENGTH: usize = 8191;
    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const TARGET_RESIDUE: u32 = 1;
}

#[cfg(feature = "encoding-bech32")]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data as Bech32 (BIP-173) strings.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types. Use [`try_to_bech32`](Self::try_to_bech32)
/// to validate the HRP and prevent cross-protocol confusion attacks.
/// Test empty and invalid HRP inputs in security-critical code.
#[cfg(feature = "encoding-bech32")]
pub trait ToBech32 {
    /// Fallibly encodes bytes as a Bech32 (BIP-173) string with optional HRP validation.
    ///
    /// Pass `expected_hrp: Some("hrp")` to enforce that the encoded HRP matches;
    /// useful for round-trip validation and preventing cross-protocol confusion.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::InvalidHrp`] — `hrp` contains invalid characters.
    /// - [`Bech32Error::UnexpectedHrp`] — `expected_hrp` is `Some` and does not match `hrp`.
    /// - [`Bech32Error::OperationFailed`] — encoding failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::ToBech32;
    ///
    /// let encoded = b"hello".try_to_bech32("test", None)?;
    /// assert!(encoded.starts_with("test1"));
    ///
    /// // HRP validation
    /// let ok = b"hello".try_to_bech32("test", Some("test"));
    /// assert!(ok.is_ok());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32(
        &self,
        hrp: &str,
        expected_hrp: Option<&str>,
    ) -> Result<alloc::string::String, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-bech32")]
impl<T: AsRef<[u8]> + ?Sized> ToBech32 for T {
    #[inline(always)]
    fn try_to_bech32(
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
        encode_lower::<Bech32Large>(hrp_parsed, self.as_ref())
            .map_err(|_| Bech32Error::OperationFailed)
    }
}

#[cfg(feature = "encoding-bech32")]
#[cfg(test)]
mod tests {
    use super::*;
    use bech32::primitives::iter::ByteIterExt;
    use bech32::{decode, encode_lower, Bech32, Fe32, Fe32IterExt, NoChecksum};

    #[test]
    fn test_bech32_large_with_checksum() {
        let large_data = vec![0u8; 1000];
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<Bech32Large>(hrp, &large_data).unwrap();

        let pos = encoded.rfind('1').unwrap();
        let hrp_str = &encoded[..pos];
        let data_str = &encoded[pos + 1..];
        let decoded_hrp = Hrp::parse(hrp_str).unwrap();
        let data_part = &data_str[..data_str.len() - 6];
        let mut fe32s = Vec::new();
        for c in data_part.chars() {
            fe32s.push(Fe32::from_char(c).unwrap());
        }
        let decoded_data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();

        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, large_data);

        let re_encoded = encode_lower::<Bech32Large>(decoded_hrp, &decoded_data).unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn test_bit_conversion_large_uncapped() {
        let large_data = vec![0u8; 4096];
        let fes: Vec<Fe32> = large_data.iter().copied().bytes_to_fes().collect();
        assert_eq!(fes.len(), (large_data.len() * 8).div_ceil(5));

        let bytes_back: Vec<u8> = fes.iter().copied().fes_to_bytes().collect();
        assert_eq!(bytes_back, large_data);
    }

    #[test]
    fn test_full_encode_decode_uncapped() {
        let large_data = vec![0u8; 1000];
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<NoChecksum>(hrp, &large_data).unwrap();
        assert!(encoded.len() > 1000 * 8 / 5);

        let s = &encoded;
        let pos = s.rfind('1').unwrap();
        let hrp_str = &s[..pos];
        let data_str = &s[pos + 1..];
        let decoded_hrp = Hrp::parse(hrp_str).unwrap();
        let mut fe32s = Vec::new();
        for c in data_str.chars() {
            fe32s.push(Fe32::from_char(c).unwrap());
        }
        let decoded_data: Vec<u8> = fe32s.iter().copied().fes_to_bytes().collect();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, large_data);
    }

    #[test]
    fn test_bip173_roundtrip() {
        let data = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"[4..].to_vec();
        let hrp = Hrp::parse("bc").unwrap();
        let encoded = encode_lower::<Bech32>(hrp, &data).unwrap();
        let (decoded_hrp, decoded_data) = decode(&encoded).unwrap();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }
}
