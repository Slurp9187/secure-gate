//! Bech32 encoding utilities, supporting both Bech32 and Bech32m variants.
//!
//! Provides `Bech32String` for secure handling of Bech32/Bech32m-encoded secrets.
//! The type stores the encoding variant and offers methods to query it,
//! decode to bytes, and access the HRP.
//!
//! Input strings may be mixed-case (as permitted by the spec). The stored string
//! is always canonical lowercase.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "encoding-bech32")]
//! # {
//! use secure_gate::encoding::bech32::Bech32String;
//!
//! let bech32 = Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
//! assert!(bech32.is_bech32());
//! # }
//! ```

#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

use alloc::string::String;

use bech32::primitives::decode::UncheckedHrpstring;
use bech32::{Bech32, Bech32m, Hrp};

/// The encoding variant used for Bech32 strings.
///
/// Bech32 and Bech32m are two similar but incompatible encoding variants.
/// Bech32m provides stronger error detection and is preferred for new applications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingVariant {
    /// Original Bech32 encoding variant.
    Bech32,
    /// Improved Bech32m encoding variant with stronger error detection.
    Bech32m,
}

fn zeroize_input(s: &mut String) {
    #[cfg(feature = "zeroize")]
    {
        zeroize::Zeroize::zeroize(s);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        let _ = s; // Suppress unused warning
    }
}

/// Detect the variant using the crate's built-in checksum validation.
///
/// `bech32::decode` accepts both variants but does not expose which succeeded.
/// We use `UncheckedHrpstring` + `validate_checksum::<Variant>()` to identify it.
fn detect_variant(s: &str) -> EncodingVariant {
    let unchecked = UncheckedHrpstring::new(s)
        .expect("string was already successfully decoded, so unchecked construction must succeed");

    if unchecked.validate_checksum::<Bech32>().is_ok() {
        EncodingVariant::Bech32
    } else {
        unchecked
            .validate_checksum::<Bech32m>()
            .expect("string passed decode, so must validate as Bech32m");
        EncodingVariant::Bech32m
    }
}

/// Validated Bech32/Bech32m string wrapper for secret data.
///
/// This struct ensures the contained string is a valid Bech32 or Bech32m encoding.
/// It lowercases the input for canonical storage and tracks which variant was detected.
///
/// # Fields
///
/// * `inner` - The validated and normalized Bech32/Bech32m string
/// * `variant` - Whether this uses Bech32 or Bech32m encoding
pub struct Bech32String {
    pub(crate) inner: crate::Dynamic<String>,
    pub(crate) variant: EncodingVariant,
}

impl Bech32String {
    /// Create a new `Bech32String` from a `String`, validating and normalizing it.
    ///
    /// Accepts mixed-case input (normalized to lowercase for storage).
    /// Rejected inputs are zeroized when the `zeroize` feature is enabled.
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        s.make_ascii_lowercase();

        if bech32::decode(&s).is_ok() {
            let variant = detect_variant(&s);
            Ok(Self {
                inner: crate::Dynamic::new(s),
                variant,
            })
        } else {
            zeroize_input(&mut s);
            Err("invalid bech32 string")
        }
    }

    /// Internal constructor for trusted (already-validated and lowercased) strings.
    ///
    /// Used by RNG encoding paths which generate canonical lowercase strings.
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String, variant: EncodingVariant) -> Self {
        Self {
            inner: crate::Dynamic::new(s),
            variant,
        }
    }

    #[cfg(feature = "encoding-bech32")]
    /// Exact number of bytes the decoded payload represents (allocation-free).
    pub fn byte_len(&self) -> usize {
        let s = self.inner.expose_secret().as_str();
        let sep_pos = s.find('1').expect("valid bech32 has '1' separator");
        let data_part_len = s.len() - sep_pos - 1;
        let data_chars = data_part_len - 6; // subtract checksum
        (data_chars * 5) / 8
    }

    #[cfg(feature = "encoding-bech32")]
    /// The Human-Readable Part (HRP) of the string.
    pub fn hrp(&self) -> Hrp {
        let (hrp, _) = bech32::decode(self.inner.expose_secret().as_str())
            .expect("Bech32String is always valid");
        hrp
    }

    #[cfg(feature = "encoding-bech32")]
    /// Get the detected encoding variant.
    pub fn variant(&self) -> EncodingVariant {
        self.variant
    }

    /// Check if this is Bech32-encoded.
    pub fn is_bech32(&self) -> bool {
        self.variant == EncodingVariant::Bech32
    }

    /// Check if this is Bech32m-encoded.
    pub fn is_bech32m(&self) -> bool {
        self.variant == EncodingVariant::Bech32m
    }

    /// Length of the encoded string (in characters).
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the encoded string is empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// Constant-time equality (prevents timing attacks when comparing encoded secrets)
#[cfg(all(feature = "encoding-bech32", feature = "ct-eq"))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.inner
            .expose_secret()
            .as_bytes()
            .ct_eq(other.inner.expose_secret().as_bytes())
    }
}

#[cfg(all(feature = "encoding-bech32", not(feature = "ct-eq")))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret() == other.inner.expose_secret()
    }
}

#[cfg(feature = "encoding-bech32")]
impl Eq for Bech32String {}

impl core::fmt::Debug for Bech32String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
