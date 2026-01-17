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
use bech32::{decode, primitives::hrp::Hrp, Bech32, Bech32m};

use crate::traits::expose_secret::ExposeSecret;

fn zeroize_input(s: &mut String) {
    #[cfg(feature = "zeroize")]
    {
        zeroize::Zeroize::zeroize(s);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        let _ = s; // Suppress unused variable warning when zeroize is disabled
    }
}

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

/// Validated Bech32/Bech32m string wrapper for secret data.
pub struct Bech32String {
    pub(crate) inner: crate::Dynamic<String>,
    pub(crate) variant: EncodingVariant,
}

impl Bech32String {
    /// Create a new `Bech32String` from a `String`, validating and normalizing it.
    ///
    /// Accepts mixed-case input (normalized to lowercase for storage).
    ///
    /// # Security Note
    ///
    /// **Invalid inputs are only securely zeroized if the `zeroize` feature is enabled.**
    /// Without `zeroize`, rejected bytes may remain in memory until the `String` is dropped
    /// normally. Enable the `zeroize` feature for secure wiping of invalid inputs.
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        let unchecked = UncheckedHrpstring::new(&s).map_err(|_| "invalid bech32 string")?;
        let variant = if unchecked.validate_checksum::<Bech32>().is_ok() {
            EncodingVariant::Bech32
        } else if unchecked.validate_checksum::<Bech32m>().is_ok() {
            EncodingVariant::Bech32m
        } else {
            zeroize_input(&mut s);
            return Err("invalid bech32 string");
        };

        // Normalize to lowercase
        s.make_ascii_lowercase();

        Ok(Self {
            inner: crate::Dynamic::new(s),
            variant,
        })
    }

    /// Check if this is a Bech32 encoding.
    #[inline(always)]
    pub fn is_bech32(&self) -> bool {
        self.variant == EncodingVariant::Bech32
    }

    /// Check if this is a Bech32m encoding.
    #[inline(always)]
    pub fn is_bech32m(&self) -> bool {
        self.variant == EncodingVariant::Bech32m
    }

    /// Get the Human-Readable Part (HRP) of the string.
    pub fn hrp(&self) -> Hrp {
        let (hrp, _) =
            decode(self.inner.expose_secret().as_str()).expect("Bech32String is always valid");
        hrp
    }

    /// Exact number of bytes the decoded payload represents (allocation-free).
    pub fn byte_len(&self) -> usize {
        let s = self.inner.expose_secret().as_str();
        let sep_pos = s.find('1').expect("valid bech32 has '1' separator");
        let data_part_len = s.len() - sep_pos - 1;
        let data_chars = data_part_len - 6; // subtract checksum
        (data_chars * 5) / 8
    }

    /// Borrowing decode: simple allocating default (most common use).
    pub fn decode(&self) -> Vec<u8> {
        let (_, data) = decode(self.inner.expose_secret().as_str())
            .expect("Bech32String invariant: always valid");
        data
    }

    /// Get the detected encoding variant.
    pub fn variant(&self) -> EncodingVariant {
        self.variant
    }

    /// Decode the validated Bech32/Bech32m string into raw bytes, consuming the wrapper.
    pub fn into_bytes(self) -> Vec<u8> {
        let (_, data) =
            decode(self.inner.expose_secret().as_str()).expect("Bech32String is always valid");
        data
    }
}

/// Constant-time equality (prevents timing attacks when comparing encoded secrets).
#[cfg(feature = "ct-eq")]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.inner
            .expose_secret()
            .as_bytes()
            .ct_eq(other.inner.expose_secret().as_bytes())
    }
}

/// Regular equality (fallback when `ct-eq` feature is not enabled).
#[cfg(not(feature = "ct-eq"))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret() == other.inner.expose_secret()
    }
}

/// Equality implementation.
impl Eq for Bech32String {}

/// Debug implementation (always redacted).
impl core::fmt::Debug for Bech32String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
