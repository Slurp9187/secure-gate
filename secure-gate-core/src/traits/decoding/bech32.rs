//! Bech32 decoding trait.
//!
//! > **Import path:** `use secure_gate::FromBech32Str;`
//!
//! This trait provides secure, explicit decoding of Bech32 strings (BIP-173 checksum)
//! to byte vectors, with HRP validation as the primary path. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32` feature** (distinct from Bech32m).
//!
//! # Security Notes
//!
//! - **Treat all input as untrusted**: validate Bech32 strings upstream before wrapping
//!   in secrets. HRP validation prevents cross-protocol confusion attacks.
//! - **HRP validation**: use [`try_from_bech32`](FromBech32Str::try_from_bech32) as the
//!   default; use [`try_from_bech32_unchecked`](FromBech32Str::try_from_bech32_unchecked)
//!   only when you intentionally need the decoded HRP. Test empty and invalid HRP inputs
//!   in security-critical code.
//! - **Heap allocation**: Returns `Vec<u8>` — wrap in [`Fixed`](crate::Fixed) or
//!   [`Dynamic`](crate::Dynamic) to store as a secret.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
//! use secure_gate::FromBech32Str;
//! # #[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
//! {
//! // BIP-173 minimal valid Bech32 test vector
//! let bech32 = "A12UEL5L";
//!
//! let data = bech32.try_from_bech32("A").expect("HRP matches");
//! assert!(data.is_empty());
//!
//! let (hrp, data) = bech32.try_from_bech32_unchecked().expect("valid bech32");
//! assert_eq!(hrp.to_ascii_lowercase(), "a");
//! assert!(data.is_empty());
//!
//! // Error on invalid input
//! assert!("not-bech32".try_from_bech32("a").is_err());
//! }
//! ```
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use super::super::encoding::bech32::{BECH32_CODE_LENGTH, Bech32Sized};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use crate::error::Bech32Error;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use alloc::string::{String, ToString};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::primitives::decode::CheckedHrpstring;

/// Extension trait for decoding Bech32 (BIP-173) strings into byte vectors.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// HRP validation prevents injection attacks and cross-protocol confusion.
///
/// **Code length**: the plain methods accept strings up to [`BECH32_CODE_LENGTH`]
/// (1023 characters, roughly 630 payload bytes). For longer strings use the
/// `_sized::<N>` methods with the same `N` — or any larger one — that produced them;
/// `N` is a length gate, not part of the encoding, so a short string written at a large
/// `N` still decodes at the default.
///
/// **The returned `Vec<u8>` is plain heap memory and is not zeroized on drop.** Wrap
/// the result in [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic) immediately
/// (or in [`zeroize::Zeroizing`]) if the decoded bytes are sensitive. Prefer
/// `Fixed::try_from_bech32` / `Dynamic::try_from_bech32`, which perform the wrapping
/// for you and zeroize their internal temporaries.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub trait FromBech32Str {
    /// Decodes a Bech32 (BIP-173) string, validating that the HRP matches `expected_hrp`.
    ///
    /// The HRP comparison is case-insensitive. Returns only the data bytes — the HRP
    /// is validated and discarded.
    ///
    /// Validates the BIP-173 checksum at [`BECH32_CODE_LENGTH`].
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
    /// let data = "A12UEL5L".try_from_bech32("A")?;
    /// assert!(data.is_empty());
    ///
    /// // HRP mismatch returns an error
    /// assert!("A12UEL5L".try_from_bech32("bc").is_err());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error>;

    /// Decodes a Bech32 (BIP-173) string into `(HRP, data_bytes)` without validating the HRP.
    ///
    /// Validates the BIP-173 checksum at [`BECH32_CODE_LENGTH`].
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::OperationFailed`] — invalid checksum, malformed string, or
    ///   bit-conversion failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::FromBech32Str;
    ///
    /// // BIP-173 minimal valid test vector
    /// let (hrp, data) = "A12UEL5L".try_from_bech32_unchecked()?;
    /// assert_eq!(hrp.to_ascii_lowercase(), "a");
    /// assert!(data.is_empty());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32_unchecked(&self) -> Result<(String, Vec<u8>), Bech32Error>;

    /// Like [`try_from_bech32`](Self::try_from_bech32), accepting strings up to `N`
    /// characters.
    ///
    /// Use the `N` the string was encoded with, or any larger value: `N` bounds the
    /// input length and never enters the checksum. See [`Bech32Sized`] for what `N`
    /// above [`BECH32_CODE_LENGTH`] costs.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::OperationFailed`] — invalid checksum, malformed string, or a
    ///   string longer than `N`.
    /// - [`Bech32Error::UnexpectedHrp`] — decoded HRP does not match `expected_hrp`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{FromBech32Str, ToBech32};
    ///
    /// let secret = [0x11u8; 900];
    /// let encoded = secret.try_to_bech32_sized::<2048>("age")?;
    /// let decoded = encoded.try_from_bech32_sized::<2048>("age")?;
    /// assert_eq!(decoded, secret);
    /// // The default code length refuses it: the string is longer than 1023.
    /// assert!(encoded.try_from_bech32("age").is_err());
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32_sized<const N: usize>(
        &self,
        expected_hrp: &str,
    ) -> Result<Vec<u8>, Bech32Error>;

    /// Like [`try_from_bech32_unchecked`](Self::try_from_bech32_unchecked), accepting
    /// strings up to `N` characters.
    fn try_from_bech32_unchecked_sized<const N: usize>(
        &self,
    ) -> Result<(String, Vec<u8>), Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromBech32Str for T {
    #[inline(always)]
    fn try_from_bech32_unchecked(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        self.try_from_bech32_unchecked_sized::<BECH32_CODE_LENGTH>()
    }

    #[inline(always)]
    fn try_from_bech32(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        self.try_from_bech32_sized::<BECH32_CODE_LENGTH>(expected_hrp)
    }

    fn try_from_bech32_unchecked_sized<const N: usize>(
        &self,
    ) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        let checked =
            CheckedHrpstring::new::<Bech32Sized<N>>(s).map_err(|_| Bech32Error::OperationFailed)?;

        // Get HRP (lowercase)
        let hrp = checked.hrp().to_string();

        // Collect data as 8-bit bytes (handles empty). `byte_iter()` is an
        // ExactSizeIterator, so this is a single exact-size allocation — no
        // reallocation copies of the payload are left on the heap.
        let data: Vec<u8> = checked.byte_iter().collect();

        Ok((hrp, data))
    }

    fn try_from_bech32_sized<const N: usize>(
        &self,
        expected_hrp: &str,
    ) -> Result<Vec<u8>, Bech32Error> {
        let s = self.as_ref();
        let checked =
            CheckedHrpstring::new::<Bech32Sized<N>>(s).map_err(|_| Bech32Error::OperationFailed)?;

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
