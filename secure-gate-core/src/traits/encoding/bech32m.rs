//! Bech32m encoding trait.
//!
//! > **Import path:** `use secure_gate::ToBech32m;`
//!
//! This trait provides secure, explicit encoding of byte data to Bech32m strings
//! (BIP-350 checksum) with a specified HRP. Designed for intentional export.
//!
//! Requires the `encoding-bech32` feature, which covers both BIP-173 and BIP-350.
//!
//! # Security Notes
//!
//! - **BIP-350 variant**: Enhanced checksum vs. BIP-173 Bech32 — use Bech32m
//!   for Taproot, SegWit v1+, and modern address formats.
//! - **Full secret exposure**: The resulting string contains the **entire** secret.
//!   Always treat output as sensitive.
//! - **Always wiped**: `try_to_bech32m` returns
//!   [`EncodedSecret`](crate::EncodedSecret), which wraps `Zeroizing<String>`, redacts
//!   its `Debug`, and wipes on drop.
//!   Addresses and other public values come back in the same wrapper. `.into_inner()` is the named point where that
//!   protection ends.
//! - **Audit visibility**: Direct wrapper calls (`key.try_to_bech32m(..., Case::Lower)`) do **not** appear in
//!   `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams or
//!   multi-step operations, prefer `with_secret(|b| b.try_to_bech32m(..., Case::Lower))` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **HRP**: pass the intended human-readable part to `try_to_bech32m`; test empty and
//!   invalid HRP inputs in security-critical code.
//! - **Caller-chosen code length**: the plain methods use [`BECH32_CODE_LENGTH`]
//!   (1023), the BCH code length the `bech32` crate itself uses and the bound within
//!   which the checksum's error-detection guarantee holds. For larger payloads use
//!   `_sized::<N>` and read the guarantee note on [`Bech32mSized`] first.
//! - **Address interoperability is narrower than the code length.** BIP-173 caps
//!   Bitcoin addresses at 90 characters, which the `bech32` crate does not enforce and
//!   neither does this crate. If you are producing Taproot/SegWit v1+ addresses, keep
//!   the payload to 20–40 bytes regardless of what the encoder will accept.
//! - **Treat all input as untrusted**: validate data upstream before wrapping.
//!
//! # Example
//!
//! ```rust
//! use secure_gate::{Case, Fixed, ToBech32m, RevealSecret};
//!
//! let secret = Fixed::new([0x00u8, 0x01]);
//!
//! // Use try_to_bech32m — the sole encoding API:
//! let encoded = secret.with_secret(|s| s.try_to_bech32m("key", Case::Lower)).unwrap();
//! assert!(encoded.starts_with("key1"));
//! // `encoded` is an `EncodedSecret`: wiped on drop, `Debug` redacted.
//! ```
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use super::Case;
#[cfg(feature = "encoding-bech32")]
use bech32::primitives::checksum::Checksum;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::Hrp;

#[cfg(feature = "encoding-bech32")]
use super::bech32::GENERATOR_SH;
#[cfg(feature = "encoding-bech32")]
pub use super::bech32::{bech32_code_length, BECH32_CODE_LENGTH};

/// Bech32m (BIP-350) checksum with a caller-chosen code length.
///
/// The bech32m twin of [`Bech32Sized`](super::bech32::Bech32Sized): identical generator,
/// different target residue, and the same rules. `N` caps the length of the whole
/// encoded string and never enters the checksum, so output is byte-identical at every
/// `N` that fits and a string decodes under any `N` at least as large as itself.
///
/// # The guarantee, and where it ends
///
/// Bech32m is a BCH code of length [`BECH32_CODE_LENGTH`] (1023), within which it
/// detects up to 4 character errors. **Above that the guarantee does not hold** — the
/// 30-bit checksum is stretched over a longer message and becomes an integrity check
/// with no proven detection bound. Still computed, still verified, no longer proven.
///
/// Separately, and more restrictively: Bitcoin address tooling expects BIP-173's
/// 90-character cap. Exceeding it produces valid bech32m that wallets will reject.
///
/// ```rust
/// use secure_gate::{Case, ToBech32m};
///
/// let blob = [0x5Au8; 900];
/// assert!(blob.try_to_bech32m("kem", Case::Lower).is_err()); // past the 1023 default
/// let encoded = blob.try_to_bech32m_sized::<2048>("kem", Case::Lower)?;
/// assert!(encoded.starts_with("kem1"));
/// # Ok::<(), secure_gate::Bech32Error>(())
/// ```
#[cfg(feature = "encoding-bech32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32mSized<const CODE_LENGTH: usize> {}

#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Checksum for Bech32mSized<N> {
    type MidstateRepr = u32;

    const CODE_LENGTH: usize = N;
    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = GENERATOR_SH;
    const TARGET_RESIDUE: u32 = 0x2bc8_30a3;
}

/// Bech32m (BIP-350) at the BCH code length, [`BECH32_CODE_LENGTH`].
///
/// The checksum's error-detection guarantee holds throughout. This is what every
/// non-`_sized` bech32m method uses, and it matches [`bech32::Bech32m`] exactly.
#[cfg(feature = "encoding-bech32")]
pub type Bech32mStandard = Bech32mSized<BECH32_CODE_LENGTH>;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data as Bech32m (BIP-350) strings.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for `AsRef<[u8]>` + [`EncodableBytes`](super::EncodableBytes). Use [`try_to_bech32m`](Self::try_to_bech32m)
/// with the protocol's HRP. Test empty and invalid HRP inputs in security-critical code.
///
/// **Design note — wallet interoperability**: `ToBech32m` targets BIP-350 (Bitcoin
/// Taproot/SegWit v1+ addresses, typically 20–40 bytes). BIP-173's 90-character cap is
/// an address convention, not a limit this encoder imposes: the plain methods accept up
/// to [`BECH32_CODE_LENGTH`] characters and [`try_to_bech32m_sized`](Self::try_to_bech32m_sized)
/// accepts whatever `N` you name. Oversized Bech32m strings are still valid bech32m and
/// still break wallets and address parsers — staying inside 90 characters for anything
/// address-shaped is your responsibility, not the type's.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
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
    /// use secure_gate::{Case, ToBech32m};
    ///
    /// let encoded = b"hello".try_to_bech32m("key", Case::Lower)?;
    /// assert!(encoded.starts_with("key1"));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32m(&self, hrp: &str, case: Case) -> Result<crate::EncodedSecret, Bech32Error>;

    /// Like [`try_to_bech32m`](Self::try_to_bech32m), with a caller-chosen code length `N`.
    ///
    /// `N` caps the length of the whole encoded string, not the payload; size it with
    /// [`bech32_code_length`]. Passing `N` greater than [`BECH32_CODE_LENGTH`] forfeits
    /// the checksum's error-detection guarantee — see [`Bech32mSized`]. Anything bound
    /// for Bitcoin address tooling should stay within 90 characters regardless of `N`.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::InvalidHrp`] — `hrp` contains invalid characters.
    /// - [`Bech32Error::OperationFailed`] — encoding failure, including a string longer
    ///   than `N`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::{Case, ToBech32m, bech32_code_length};
    ///
    /// const N: usize = bech32_code_length(3, 1568); // ML-KEM-1024 ciphertext
    /// let ct = [0x5Au8; 1568];
    /// let encoded = ct.try_to_bech32m_sized::<N>("kem", Case::Lower)?;
    /// assert!(encoded.starts_with("kem1"));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32m_sized<const N: usize>(
        &self,
        hrp: &str,
        case: Case,
    ) -> Result<crate::EncodedSecret, Bech32Error>;
}

// Blanket impl over AsRef<[u8]> + EncodableBytes (e.g. &[u8], Vec<u8>, [u8; N]).
// encode_lower returns String — requires alloc.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
impl<T: AsRef<[u8]> + super::EncodableBytes + ?Sized> ToBech32m for T {
    #[inline(always)]
    fn try_to_bech32m(&self, hrp: &str, case: Case) -> Result<crate::EncodedSecret, Bech32Error> {
        self.try_to_bech32m_sized::<BECH32_CODE_LENGTH>(hrp, case)
    }

    #[inline(always)]
    fn try_to_bech32m_sized<const N: usize>(
        &self,
        hrp: &str,
        case: Case,
    ) -> Result<crate::EncodedSecret, Bech32Error> {
        let hrp_parsed = Hrp::parse(hrp).map_err(|_| Bech32Error::InvalidHrp)?;
        let data = self.as_ref();
        let len = bech32_code_length(hrp.len(), data.len());
        if len > N {
            return Err(Bech32Error::OperationFailed);
        }
        // Drive `bech32`'s iterator primitives straight into a buffer reserved to the
        // exact final length. This is what `bech32::encode_lower_to_fmt` does too,
        // except that it stages every output character through a 1 KiB stack array
        // (`[0u8; BUF_LENGTH]`) it never wipes, so the encoded secret survived in that
        // frame after the call returned. Adversarial review found it; the crate's own
        // guarantee is about the heap, but "wiped on drop" should not have a stack
        // footnote. The chain below holds one pending byte, a bit offset and a `u32`
        // checksum midstate -- a unit test pins its size -- and each char goes into
        // `out` as it is produced. One allocation, no intermediate copy anywhere.
        //
        // The CODE_LENGTH gate that `encode_lower_to_fmt` applied via `encoded_length`
        // is replicated exactly: refuse when the whole string would exceed N.
        let mut out = alloc::string::String::with_capacity(len);
        let chain = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32mSized<N>>(&hrp_parsed)
            .chars();
        for c in chain {
            out.push(c);
        }
        debug_assert_eq!(
            out.len(),
            len,
            "bech32_code_length disagreed with the encoder"
        );
        // BIP-173 defines the checksum over the lowercase form and accepts either pure
        // case, so uppercasing the finished string -- HRP, separator, payload and
        // checksum together -- stays valid and decodable. Done here, on a buffer we
        // still own at exact capacity: ASCII case conversion is length-preserving, so
        // it cannot reallocate and the secret is never copied.
        if matches!(case, Case::Upper) {
            out.make_ascii_uppercase();
        }
        Ok(crate::EncodedSecret::new(out))
    }
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Byte-for-byte equivalence with upstream's encoder for the bech32m chain.
    #[test]
    fn direct_chain_matches_upstream_encode_lower() {
        use bech32::{encode_lower, Hrp};
        for (hrp, len) in [
            ("a", 0usize),
            ("kem", 32),
            ("kem", 633),
            ("kem", 1568),
            ("x", 4096),
        ] {
            let data: alloc::vec::Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
            let ours = data
                .try_to_bech32m_sized::<65535>(hrp, Case::Lower)
                .expect("ours");
            let theirs = encode_lower::<Bech32mSized<65535>>(Hrp::parse(hrp).unwrap(), &data)
                .expect("upstream");
            assert_eq!(&*ours, &*theirs, "hrp={hrp} len={len}");
        }
    }

    #[test]
    fn default_code_length_rejects_oversized_payload() {
        // 800 bytes is 1280 base32 characters, past BECH32_CODE_LENGTH.
        let large_data = vec![0u8; 800];
        assert_eq!(
            large_data.try_to_bech32m("test", Case::Lower).unwrap_err(),
            crate::error::Bech32Error::OperationFailed
        );
    }

    #[test]
    fn sized_accepts_what_the_default_rejects() {
        let large_data = vec![0u8; 800];
        assert!(large_data.try_to_bech32m("test", Case::Lower).is_err());
        let encoded = large_data
            .try_to_bech32m_sized::<2048>("test", Case::Lower)
            .expect("2048 is long enough");
        assert!(encoded.starts_with("test1"));
    }
}
