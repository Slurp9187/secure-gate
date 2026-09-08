//! Bech32m decoding trait.
//!
//! > **Import path:** `use secure_gate::FromBech32mStr;`
//!
//! This trait provides secure, explicit decoding of Bech32m strings (BIP-350 checksum)
//! to byte vectors, with HRP validation as the primary path. It is designed for handling
//! untrusted input in cryptographic contexts, such as decoding encoded addresses or keys.
//!
//! **Requires the `encoding-bech32` feature**, which covers both BIP-173 and BIP-350.
//! The two are distinct checksums; one feature ships both.
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
//! - **Code length**: the plain methods accept strings up to
//!   [`BECH32_CODE_LENGTH`] (1023 characters). Use
//!   `try_from_bech32m_sized::<N>` for longer ones. Note that Bitcoin address tooling
//!   expects BIP-173's much narrower 90-character convention.
//! - **Bech32 and Bech32m are different checksums**, not different size classes:
//!   a BIP-173 string never decodes here at any code length. Use
//!   [`FromBech32Str`](crate::FromBech32Str) for those.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::FromBech32mStr;
//! # #[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
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
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use super::super::encoding::bech32m::{Bech32mSized, BECH32_CODE_LENGTH};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use crate::error::Bech32Error;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use alloc::string::{String, ToString};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::primitives::decode::CheckedHrpstring;

/// Extension trait for decoding Bech32m (BIP-350) strings into byte vectors.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for all `AsRef<str>` types. Treat all input as untrusted;
/// HRP validation prevents injection attacks and cross-protocol confusion.
///
/// **Design note**: this decodes the BIP-350 checksum. Strings written by
/// [`ToBech32`](crate::ToBech32) carry the BIP-173 checksum and never decode here,
/// whatever the code length — use [`FromBech32Str`](crate::FromBech32Str) for those.
/// Length is a separate axis: see `try_from_bech32m_sized`.
///
/// **The returned `Vec<u8>` is plain heap memory and is not zeroized on drop.** Wrap
/// the result in [`Fixed`](crate::Fixed) or [`Dynamic`](crate::Dynamic) immediately
/// (or in [`zeroize::Zeroizing`]) if the decoded bytes are sensitive. Prefer
/// `Fixed::try_from_bech32m` / `Dynamic::try_from_bech32m`, which perform the
/// wrapping for you and zeroize their internal temporaries.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
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
    /// - [`Bech32Error::OperationFailed`] — invalid checksum, malformed string, or
    ///   bit-conversion failure.
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

    /// Like [`try_from_bech32m`](Self::try_from_bech32m), accepting strings up to `N`
    /// characters.
    ///
    /// Use the `N` the string was encoded with, or any larger value: `N` bounds the
    /// input length and never enters the checksum. See
    /// [`Bech32mSized`] for what `N` above
    /// [`BECH32_CODE_LENGTH`] costs.
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
    /// use secure_gate::{FromBech32mStr, ToBech32m};
    ///
    /// let ct = [0x5Au8; 1568];
    /// let encoded = ct.try_to_bech32m_sized::<4096>("kem")?;
    /// let decoded = encoded.try_from_bech32m_sized::<4096>("kem")?;
    /// assert_eq!(decoded, ct);
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_from_bech32m_sized<const N: usize>(
        &self,
        expected_hrp: &str,
    ) -> Result<Vec<u8>, Bech32Error>;

    /// Like [`try_from_bech32m_unchecked`](Self::try_from_bech32m_unchecked), accepting
    /// strings up to `N` characters.
    fn try_from_bech32m_unchecked_sized<const N: usize>(
        &self,
    ) -> Result<(String, Vec<u8>), Bech32Error>;
}

// Blanket impl to cover any AsRef<str> (e.g., &str, String, etc.)
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
impl<T: AsRef<str> + ?Sized> FromBech32mStr for T {
    #[inline(always)]
    fn try_from_bech32m_unchecked(&self) -> Result<(String, Vec<u8>), Bech32Error> {
        self.try_from_bech32m_unchecked_sized::<BECH32_CODE_LENGTH>()
    }

    #[inline(always)]
    fn try_from_bech32m(&self, expected_hrp: &str) -> Result<Vec<u8>, Bech32Error> {
        self.try_from_bech32m_sized::<BECH32_CODE_LENGTH>(expected_hrp)
    }

    fn try_from_bech32m_unchecked_sized<const N: usize>(
        &self,
    ) -> Result<(String, Vec<u8>), Bech32Error> {
        let s = self.as_ref();
        let checked = CheckedHrpstring::new::<Bech32mSized<N>>(s)
            .map_err(|_| Bech32Error::OperationFailed)?;

        // Get HRP (lowercase)
        let hrp = checked.hrp().to_string();

        // Collect data as 8-bit bytes (handles empty). `byte_iter()` is an
        // ExactSizeIterator, so this is a single exact-size allocation — no
        // reallocation copies of the payload are left on the heap.
        let data: Vec<u8> = checked.byte_iter().collect();

        Ok((hrp, data))
    }

    fn try_from_bech32m_sized<const N: usize>(
        &self,
        expected_hrp: &str,
    ) -> Result<Vec<u8>, Bech32Error> {
        let s = self.as_ref();
        let checked = CheckedHrpstring::new::<Bech32mSized<N>>(s)
            .map_err(|_| Bech32Error::OperationFailed)?;

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
