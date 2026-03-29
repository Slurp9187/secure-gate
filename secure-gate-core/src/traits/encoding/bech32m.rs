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
//! - **Zeroizing variants**: Prefer `try_to_bech32m_zeroizing`, which returns [`EncodedSecret`]
//!   (wrapping `Zeroizing<String>` with redacted `Debug`) when the encoded form remains sensitive.
//! - **Audit visibility**: Direct wrapper calls (`key.try_to_bech32m(...)`) do **not** appear in
//!   `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams or
//!   multi-step operations, prefer `with_secret(|b| b.try_to_bech32m(...))` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **HRP**: pass the intended human-readable part to `try_to_bech32m`; test empty and
//!   invalid HRP inputs in security-critical code.
//! - **Standard BIP-350 payload limit (~90 bytes)**: intentionally kept at spec
//!   compliance for interoperability with Bitcoin Taproot/SegWit v1+ tooling.
//!   For non-address use cases with large payloads (age-style encryption recipients,
//!   ciphertexts), use [`ToBech32`](crate::ToBech32) / [`FromBech32Str`](crate::FromBech32Str)
//!   which use the extended `Bech32Large` variant (~5 KB (5,115 bytes maximum payload)).
//! - **Treat all input as untrusted**: validate data upstream before wrapping.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{Fixed, ToBech32m, RevealSecret};
//!
//! let secret = Fixed::new([0x00u8, 0x01]);
//!
//! // Use try_to_bech32m — the sole encoding API:
//! let encoded = secret.with_secret(|s| s.try_to_bech32m("key")).unwrap();
//! assert!(encoded.starts_with("key1"));
//!
//! // Zeroizing variant for sensitive encoded output:
//! let encoded_z = secret.try_to_bech32m_zeroizing("key")?;
//! assert!(encoded_z.starts_with("key1"));
//! // encoded_z is EncodedSecret — zeroized on drop, redacted Debug
//! # Ok::<(), secure_gate::Bech32Error>(())
//! ```
#[cfg(feature = "encoding-bech32m")]
use bech32::{encode_lower, Bech32m, Hrp};

#[cfg(feature = "encoding-bech32m")]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data as Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32m`.*
///
/// Blanket-implemented for all `AsRef<[u8]>` types. Use [`try_to_bech32m`](Self::try_to_bech32m)
/// with the protocol's HRP. Test empty and invalid HRP inputs in security-critical code.
///
/// **Design note — intentional size asymmetry**: `ToBech32m` targets BIP-350
/// (Bitcoin Taproot/SegWit v1+ addresses, typically 20–40 bytes). The 90-byte spec
/// limit is deliberate; oversized Bech32m strings break interoperability with wallets
/// and address parsers. For large secrets (encryption recipients, ciphertexts,
/// arbitrary keys ≥ ~50 bytes), use [`ToBech32`](crate::ToBech32) / `Bech32Large`.
#[cfg(feature = "encoding-bech32m")]
pub trait ToBech32m {
    /// Fallibly encodes bytes as a Bech32m (BIP-350) string with the given HRP.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::InvalidHrp`] — `hrp` contains invalid characters.
    /// - [`Bech32Error::OperationFailed`] — encoding failure (e.g., data too large).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::ToBech32m;
    ///
    /// let encoded = b"hello".try_to_bech32m("key")?;
    /// assert!(encoded.starts_with("key1"));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, Bech32Error>;

    /// Fallibly encodes bytes as Bech32m and wraps the result in [`crate::EncodedSecret`].
    fn try_to_bech32m_zeroizing(&self, hrp: &str) -> Result<crate::EncodedSecret, Bech32Error>;
}

// Blanket impl to cover any AsRef<[u8]> (e.g., &[u8], Vec<u8>, [u8; N], etc.)
#[cfg(feature = "encoding-bech32m")]
impl<T: AsRef<[u8]> + ?Sized> ToBech32m for T {
    #[inline(always)]
    fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, Bech32Error> {
        let hrp_parsed = Hrp::parse(hrp).map_err(|_| Bech32Error::InvalidHrp)?;
        encode_lower::<Bech32m>(hrp_parsed, self.as_ref()).map_err(|_| Bech32Error::OperationFailed)
    }

    #[inline(always)]
    fn try_to_bech32m_zeroizing(&self, hrp: &str) -> Result<crate::EncodedSecret, Bech32Error> {
        self.try_to_bech32m(hrp).map(crate::EncodedSecret::new)
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
