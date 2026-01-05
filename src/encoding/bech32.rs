//! Bech32 encoding utilities, supporting both Bech32 and Bech32m variants.
//!
//! Provides `Bech32String` for secure handling of Bech32-encoded secrets.
//! The type stores the encoding variant and offers methods to query it,
//! decode to bytes, and access the HRP.
//!
//! # Examples
//!
//! Create a Bech32 string:
//! ```
//! # #[cfg(feature = "encoding-bech32")]
//! # {
//! use secure_gate::encoding::bech32::Bech32String;
//! let bech32 = Bech32String::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()).unwrap();
//! assert!(bech32.is_bech32());
//! # }
//! ```

// ==========================================================================
// src/encoding/bech32.rs
// ==========================================================================

// Allow unsafe_code when zeroize is enabled (needed for bech32 string validation)
// but forbid it otherwise
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

use alloc::string::String;
use bech32::{Bech32, Hrp};

pub(crate) fn convert_bits(
    data: &[u8],
    from: usize,
    to: usize,
    pad: bool,
) -> Result<Vec<u8>, &'static str> {
    if from > 8 || to > 8 {
        return Err("invalid bit group");
    }
    let mut acc = 0usize;
    let mut bits = 0usize;
    let mut ret = Vec::new();
    let maxv = (1 << to) - 1;
    for &v in data {
        if (v as usize >> from) != 0 {
            return Err("invalid bit group");
        }
        acc = (acc << from) | (v as usize);
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err("invalid padding");
    }
    Ok(ret)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingVariant {
    Bech32,
    Bech32m,
}

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

/// Validated, Bech32 string wrapper for secret data.
///
/// This struct ensures the contained string is valid Bech32 or Bech32m encoding.
/// Provides methods for decoding back to bytes.
///
pub struct Bech32String {
    inner: crate::Dynamic<String>,
    variant: EncodingVariant,
}

impl Bech32String {
    /// Create a new `Bech32String` from a `String`, validating it as Bech32.
    ///
    /// The input `String` is consumed. If validation fails and the `zeroize` feature
    /// is enabled, the rejected bytes are zeroized before the error is returned.
    ///
    /// Validation rules:
    /// - Valid Bech32 checksum and character set via `bech32::decode`
    /// - Accepts uppercase (normalized to lowercase)
    ///
    /// # Errors
    ///
    /// Returns `Err("invalid bech32 string")` if validation fails.
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        match bech32::decode(&s) {
            Ok((hrp, data)) => {
                let normalized = bech32::encode::<Bech32>(hrp, &data)
                    .expect("re-encoding valid input should succeed");

                Ok(Self {
                    inner: crate::Dynamic::new(normalized),
                    variant: EncodingVariant::Bech32,
                })
            }
            Err(_) => {
                zeroize_input(&mut s);
                Err("invalid bech32 string")
            }
        }
    }

    /// Internal constructor for trusted Bech32 strings (e.g., from validated sources).
    ///
    /// Skips validation – caller must ensure the string is valid Bech32 or Bech32m.
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String, variant: EncodingVariant) -> Self {
        Self {
            inner: crate::Dynamic::new(s),
            variant,
        }
    }

    /// Decode the validated Bech32 string back into raw bytes (5-to-8 bit conversion).
    ///
    /// Panics if the internal string is somehow invalid (impossible under correct usage).
    pub fn decode_secret_to_bytes(&self) -> Vec<u8> {
        let (_, data) =
            bech32::decode(self.inner.expose_secret()).expect("Bech32String is always valid");
        convert_bits(&data, 5, 8, false).unwrap()
    }

    /// Number of bytes the decoded Bech32 string represents.
    pub fn byte_len(&self) -> usize {
        let s = self.expose_secret();
        let sep_pos = s.find('1').expect("valid bech32 has '1' separator");
        let data_part_len = s.len() - sep_pos - 1; // everything after '1'
        let data_chars = data_part_len - 6; // drop checksum (always 6 chars)
        (data_chars * 5) / 8
    }

    /// The Human-Readable Part of the Bech32 string.
    pub fn hrp(&self) -> Hrp {
        let (hrp, _) =
            bech32::decode(self.inner.expose_secret()).expect("Bech32String is always valid");
        hrp
    }

    /// Get the encoding variant.
    pub fn variant(&self) -> EncodingVariant {
        self.variant
    }

    /// Check if this is a Bech32 encoded string.
    pub fn is_bech32(&self) -> bool {
        self.variant == EncodingVariant::Bech32
    }

    /// Check if this is a Bech32m encoded string.
    pub fn is_bech32m(&self) -> bool {
        self.variant == EncodingVariant::Bech32m
    }

    /// Primary way to access the validated string — returns &String for consistency
    #[inline(always)]
    pub const fn expose_secret(&self) -> &String {
        self.inner.expose_secret()
    }

    /// Length of the encoded string (in characters) — delegate directly
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the encoded string is empty — delegate directly
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// Constant-time equality for bech32 strings – prevents timing attacks when ct-eq enabled
#[cfg(all(feature = "encoding-bech32", feature = "ct-eq"))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        use crate::eq::ConstantTimeEq;
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
