//! Bech32m decoding trait.
//!
//! > **Import path:** `use secure_gate::FromBech32mStr;`
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum)
//! to byte vectors, with HRP validation as the primary path. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32m` feature** (distinct from classic Bech32).
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate Bech32m strings upstream before wrapping
//!   in secrets. HRP validation prevents cross-protocol confusion attacks.
//! - **HRP validation**: use [`try_from_bech32m`](FromBech32mStr::try_from_bech32m) as the
//!   default; use [`try_from_bech32m_unchecked`](FromBech32mStr::try_from_bech32m_unchecked)
//!   only when you intentionally need the decoded HRP. Test empty and invalid HRP inputs
//!   in security-critical code.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//! - **BIP-350 checksum**: Enhanced error detection over BIP-173 Bech32.
//! - **Standard 90-byte payload limit (by design)**: decodes only spec-compliant
//!   Bech32m strings intended for Bitcoin address formats. Strings produced by
//!   the extended [`ToBech32`](crate::ToBech32) / `Bech32Large` variant are a
//!   distinct format — decode those with [`FromBech32Str`](crate::FromBech32Str).
//!
//! # Example
//!
//! ```rust
//! use secure_gate::FromBech32mStr;
//! # #[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
//! # {
//!
//! // BIP-350 minimal valid Bech32m test vector
//! let bech32m = "A1LQFN3A";
//!
//! let data = bech32m.try_from_bech32m("A").expect("HRP matches");
//! assert!(data.is_empty());
//!
//! let (hrp, data) = bech32m.try_from_bech32m_unchecked().expect("valid bech32m");
//! assert_eq!(hrp.to_ascii_lowercase(), "a");
//! assert!(data.is_empty());
//!
//! // Error on invalid input
//! assert!("not-bech32m".try_from_bech32m("a").is_err());
//! # }
//! ```
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use crate::error::Bech32Error;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use alloc::string::{String, ToString};
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
use bech32::{primitives::decode::CheckedHrpstring, Bech32m};

/// Extension trait for decoding Bech32m (BIP-350) strings into byte vectors.
///
/// *Requires feature `encoding-bech32m`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// HRP validation prevents injection attacks and cross-protocol confusion.
///
/// **Design note — standard BIP-350 compliance**: decodes only standard-length
/// Bech32m strings (Bitcoin Taproot/SegWit v1+ compatible). The `Bech32Large`
/// variant used by [`ToBech32`](crate::ToBech32) is a distinct non-standard format
/// for large payloads; decode those with [`FromBech32Str`](crate::FromBech32Str).
///
/// **The returned `Vec<u8>` is plain heap memory and is not zeroized on drop.** Wrap
/// the result in [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic) immediately
/// (or in [`zeroize::Zeroizing`]) if the decoded bytes are sensitive. Prefer
/// `Fixed::try_from_bech32m` / `Dynamic::try_from_bech32m`, which perform the
/// wrapping for you and zeroize their internal temporaries.
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
pub trait FromBech32mStr {
    /// Decodes a Bech32m (BIP-350) string, validating that the HRP matches `expected_hrp`.
    ///
    /// The HRP comparison is case-insensitive. Returns only the data bytes — the HRP
    /// is validated and discarded.
    ///
    /// Validates the BIP-350 checksum.
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
    /// let data = "A1LQFN3A".try_from_bech32m("A")?;
    /// assert!(data.is_empty());
    ///
    /// // HRP mismatch returns an error
    /// assert!("A1LQFN3A".try_from_bech32m("bc").is_err());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32m(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;

    /// Decodes a Bech32m (BIP-350) string into `(HRP, data_bytes)` without validating the HRP.
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
    /// let (hrp, data) = "A1LQFN3A".try_from_bech32m_unchecked()?;
    /// assert_eq!(hrp.to_ascii_lowercase(), "a");
    /// assert!(data.is_empty());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32m_unchecked(&self) -> Result<(String, Vec<u8>), Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(all(feature = "encoding-bech32m", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromBech32mStr for T {
    fn try_from_bech32m_unchecked(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        // Use CheckedHrpstring to validate Bech32m checksum (no-alloc)
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Bech32Error::OperationFailed)?;

        // Get HRP (lowercase)
        let hrp = checked.hrp().to_string();

        // Collect data as 8-bit bytes (handles empty). `byte_iter()` is an
        // ExactSizeIterator, so this is a single exact-size allocation — no
        // reallocation copies of the payload are left on the heap.
        let data: Vec<u8> = checked.byte_iter().collect();

        Ok((hrp, data))
    }

    fn try_from_bech32m(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        let s = self.as_ref();
        let checked =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|_| Bech32Error::OperationFailed)?;

        // Validate the HRP *before* materializing any payload bytes, so an
        // HRP mismatch never leaves decoded secret material in unzeroized
        // memory. (Case-insensitive comparison — timing leak is acceptable
        // since the HRP is public metadata.)
        if !checked.hrp().as_str().eq_ignore_ascii_case(expected_hrp) {
            return Err(Bech32Error::UnexpectedHrp);
        }

        // Single exact-size allocation (byte_iter is an ExactSizeIterator).
        Ok(checked.byte_iter().collect())
    }
}
