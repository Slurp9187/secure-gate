//! Bech32 encoding trait.
//!
//! > **Import path:** `use secure_gate::ToBech32;`
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
//! - **Always wiped**: `try_to_bech32` returns
//!   [`EncodedSecret`](crate::EncodedSecret), which wraps `Zeroizing<String>`, redacts
//!   its `Debug`, and wipes on drop.
//!   Addresses and other public values come back in the same wrapper. `.into_inner()` is the named point where that
//!   protection ends.
//! - **Audit visibility**: Direct wrapper calls (`key.try_to_bech32(...)`) do **not** appear in
//!   `grep expose_secret` / `grep with_secret` audit sweeps. For audit-first teams or
//!   multi-step operations, prefer `with_secret(|b| b.try_to_bech32(...))` — the borrow
//!   checker enforces the reference cannot escape the closure.
//! - **HRP**: pass the intended human-readable part to `try_to_bech32`; test empty and
//!   invalid HRP inputs in security-critical code.
//! - **Caller-chosen code length**: the plain methods use [`BECH32_CODE_LENGTH`]
//!   (1023), the length at which the BCH checksum retains its error-detection
//!   guarantee. For larger payloads — age-style recipients, KEM ciphertexts,
//!   arbitrary binary blobs — use the `_sized::<N>` methods with an explicit `N`
//!   and read the guarantee note on [`Bech32Sized`] first.
//!   For Bitcoin address formats, use [`ToBech32m`](crate::ToBech32m) (BIP-350).
//! - **Treat all input as untrusted**: validate data upstream before wrapping.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "encoding-bech32")]
//! use secure_gate::{Fixed, ToBech32, RevealSecret};
//! # #[cfg(feature = "encoding-bech32")]
//! {
//! let secret = Fixed::new([0x42u8; 4]);
//!
//! // Use try_to_bech32 — the sole encoding API:
//! let encoded = secret.with_secret(|s| s.try_to_bech32("test")).unwrap();
//! assert!(encoded.starts_with("test1"));
//! }
//! ```
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::Hrp;
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};

#[cfg(feature = "encoding-bech32")]
use bech32::primitives::checksum::Checksum;

/// Bech32/Bech32m generator coefficients (BIP-173 § Checksum, Bitcoin Core `bech32.cpp`).
/// Identical for both checksums; only `TARGET_RESIDUE` differs.
#[cfg(feature = "encoding-bech32")]
pub(crate) const GENERATOR_SH: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// The code length of the bech32 BCH code: **1023**.
///
/// This is the value the `bech32` crate itself uses for both [`bech32::Bech32`] and
/// [`bech32::Bech32m`], and it is the length up to which the checksum's error-detection
/// guarantee holds. Every non-`_sized` method in this crate uses it.
///
/// It is *not* BIP-173's 90-character limit: that is a convention for Bitcoin addresses
/// which the `bech32` crate deliberately does not enforce. 1023 characters is roughly
/// 630 payload bytes, depending on HRP length — see [`bech32_code_length`].
#[cfg(feature = "encoding-bech32")]
pub const BECH32_CODE_LENGTH: usize = 1023;

/// The code length required to encode `payload_bytes` under an HRP of `hrp_len` characters.
///
/// Accounts for every component of the string, which the payload figure alone does not:
/// HRP + the `1` separator + the base32 payload (8 bits in, 5 bits out, rounded up) +
/// the 6-character checksum. Use it to pick an `N` for the `_sized` methods:
///
/// ```rust
/// use secure_gate::{ToBech32, bech32_code_length};
///
/// const N: usize = bech32_code_length(3, 4096); // hrp "age", 4 KiB payload
/// let blob = [0xA5u8; 4096];
/// let encoded = blob.try_to_bech32_sized::<N>("age")?;
/// assert!(encoded.starts_with("age1"));
/// # Ok::<(), secure_gate::Bech32Error>(())
/// ```
///
/// Values above [`BECH32_CODE_LENGTH`] forfeit the checksum's error-detection guarantee
/// — see [`Bech32Sized`].
#[cfg(feature = "encoding-bech32")]
#[must_use]
pub const fn bech32_code_length(hrp_len: usize, payload_bytes: usize) -> usize {
    // ceil(payload_bytes * 8 / 5) base32 characters, plus HRP, separator, checksum.
    //
    // Saturating rather than wrapping: for a payload whose encoding cannot fit in a
    // `usize` at all the result is `usize::MAX`, which every encoder then refuses. It
    // never panics and never returns a value smaller than the truth. (Adversarial
    // review: the plain `payload_bytes * 8` panicked in debug and wrapped in release.)
    // ceil(8b / 5) computed as 8·(b/5) + ceil(8·(b%5) / 5), which cannot overflow
    // until the true answer itself no longer fits in a usize.
    let payload_chars = (payload_bytes / 5)
        .saturating_mul(8)
        .saturating_add(((payload_bytes % 5) * 8).div_ceil(5));
    hrp_len
        .saturating_add(1)
        .saturating_add(payload_chars)
        .saturating_add(6)
}

/// Bech32 (BIP-173) checksum with a caller-chosen code length.
///
/// `N` is the maximum length of the whole encoded string — HRP, separator, payload and
/// checksum together. It is a **length gate only**: `N` never enters the checksum
/// computation, so the same bytes and HRP produce byte-identical output at every `N`,
/// and a string is decodable by any `N` at least as large as the string.
///
/// # The guarantee, and where it ends
///
/// The bech32 checksum is a BCH code of length [`BECH32_CODE_LENGTH`] (1023). Within
/// that length it is guaranteed to detect up to 4 character errors. **Above it, that
/// guarantee does not hold** — the same 30-bit checksum is stretched over a longer
/// message, and it degrades to an integrity check with no proven detection bound. It is
/// still computed and verified; it simply stops promising what BIP-173 proves.
///
/// Choosing `N > 1023` is therefore a deliberate trade, which is why it is spelled at
/// the call site rather than baked into a default. For payloads that fit, prefer
/// [`Bech32Standard`].
///
/// ```rust
/// use secure_gate::ToBech32;
///
/// // A 2 KiB KEM ciphertext needs a code length well past the BCH bound.
/// let ct = [0x5Au8; 2048];
/// let encoded = ct.try_to_bech32_sized::<4096>("kyber")?;
/// assert!(encoded.starts_with("kyber1"));
/// # Ok::<(), secure_gate::Bech32Error>(())
/// ```
#[cfg(feature = "encoding-bech32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32Sized<const CODE_LENGTH: usize> {}

#[cfg(feature = "encoding-bech32")]
impl<const N: usize> Checksum for Bech32Sized<N> {
    type MidstateRepr = u32;

    const CODE_LENGTH: usize = N;
    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = GENERATOR_SH;
    const TARGET_RESIDUE: u32 = 1;
}

/// Bech32 (BIP-173) at the BCH code length, [`BECH32_CODE_LENGTH`].
///
/// The checksum's error-detection guarantee holds throughout. This is what every
/// non-`_sized` bech32 method uses.
#[cfg(feature = "encoding-bech32")]
pub type Bech32Standard = Bech32Sized<BECH32_CODE_LENGTH>;

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
use crate::error::Bech32Error;

/// Extension trait for encoding byte data as Bech32 (BIP-173) strings.
///
/// *Requires feature `encoding-bech32`.*
///
/// Blanket-implemented for `AsRef<[u8]>` + [`EncodableBytes`](super::EncodableBytes). Use [`try_to_bech32`](Self::try_to_bech32)
/// with the protocol's HRP. Test empty and invalid HRP inputs in security-critical code.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
pub trait ToBech32 {
    /// Fallibly encodes bytes as a Bech32 (BIP-173) string with the given HRP.
    ///
    /// # Errors
    ///
    /// - [`Bech32Error::InvalidHrp`] — `hrp` contains invalid characters.
    /// - [`Bech32Error::OperationFailed`] — encoding failure.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secure_gate::ToBech32;
    ///
    /// let encoded = b"hello".try_to_bech32("test")?;
    /// assert!(encoded.starts_with("test1"));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32(&self, hrp: &str) -> Result<crate::EncodedSecret, Bech32Error>;

    /// Like [`try_to_bech32`](Self::try_to_bech32), with a caller-chosen code length `N`.
    ///
    /// `N` caps the length of the whole encoded string, not the payload; size it with
    /// [`bech32_code_length`]. Output is byte-identical to `try_to_bech32` for any input
    /// that fits both, because `N` is a length gate and never enters the checksum.
    ///
    /// Passing `N` greater than [`BECH32_CODE_LENGTH`] forfeits the checksum's
    /// error-detection guarantee — see [`Bech32Sized`].
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
    /// use secure_gate::ToBech32;
    ///
    /// let recipient = [0x11u8; 900];
    /// // 900 bytes does not fit the default 1023-character code length.
    /// assert!(recipient.try_to_bech32("age").is_err());
    /// let encoded = recipient.try_to_bech32_sized::<2048>("age")?;
    /// assert!(encoded.starts_with("age1"));
    /// # Ok::<(), secure_gate::Bech32Error>(())
    /// ```
    fn try_to_bech32_sized<const N: usize>(
        &self,
        hrp: &str,
    ) -> Result<crate::EncodedSecret, Bech32Error>;
}

// Blanket impl over AsRef<[u8]> + EncodableBytes (e.g. &[u8], Vec<u8>, [u8; N]).
// encode_lower returns String — requires alloc.
#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
impl<T: AsRef<[u8]> + super::EncodableBytes + ?Sized> ToBech32 for T {
    #[inline(always)]
    fn try_to_bech32(&self, hrp: &str) -> Result<crate::EncodedSecret, Bech32Error> {
        self.try_to_bech32_sized::<BECH32_CODE_LENGTH>(hrp)
    }

    #[inline(always)]
    fn try_to_bech32_sized<const N: usize>(
        &self,
        hrp: &str,
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
            .with_checksum::<Bech32Sized<N>>(&hrp_parsed)
            .chars();
        for c in chain {
            out.push(c);
        }
        debug_assert_eq!(
            out.len(),
            len,
            "bech32_code_length disagreed with the encoder"
        );
        Ok(crate::EncodedSecret::new(out))
    }
}

#[cfg(all(feature = "encoding-bech32", feature = "alloc"))]
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use bech32::primitives::iter::ByteIterExt;
    use bech32::{Bech32, Fe32, Fe32IterExt, NoChecksum, decode, encode_lower};

    /// The encoder chain holds no payload-sized state. `encode_lower_to_fmt` staged
    /// output through a 1 KiB stack array; this crate now drives the chain directly,
    /// and the chain itself is a pending byte, a bit offset, a borrowed HRP, and a
    /// `u32` checksum midstate — 72 bytes on x86_64. If someone reintroduces a staging
    /// buffer inside the chain, this number grows and the test says so. The bound is
    /// 96 rather than 72 so that pointer-width and padding differences across targets
    /// do not fail it; anything staging a payload would be orders of magnitude over.
    #[test]
    fn encoder_chain_carries_no_staging_buffer() {
        let data = [0xABu8; 1568];
        let hrp = Hrp::parse("age").unwrap();
        let chain = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32Sized<4096>>(&hrp)
            .chars();
        let size = core::mem::size_of_val(&chain);
        assert!(
            size <= 96,
            "encoder chain is {size} bytes -- something payload-sized is being staged"
        );
    }

    /// Byte-for-byte equivalence with upstream's encoder, so bypassing its staging
    /// buffer changed nothing observable except the stack.
    #[test]
    fn direct_chain_matches_upstream_encode_lower() {
        use bech32::encode_lower;
        for (hrp, len) in [
            ("a", 0usize),
            ("age", 1),
            ("age", 4),
            ("age", 32),
            ("kem", 633),
            ("age", 634),
            ("kem", 1568),
            ("x", 4096),
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
            let ours = data.try_to_bech32_sized::<65535>(hrp).expect("ours");
            let theirs = encode_lower::<Bech32Sized<65535>>(Hrp::parse(hrp).unwrap(), &data)
                .expect("upstream");
            assert_eq!(&*ours, &*theirs, "hrp={hrp} len={len}");
        }
    }

    #[test]
    fn test_bech32_sized_with_checksum() {
        let large_data = vec![0u8; 1000];
        let hrp = Hrp::parse("test").unwrap();
        let encoded = encode_lower::<Bech32Sized<2048>>(hrp, &large_data).unwrap();

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

        let re_encoded = encode_lower::<Bech32Sized<2048>>(decoded_hrp, &decoded_data).unwrap();
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
