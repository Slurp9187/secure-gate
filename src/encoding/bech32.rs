// ==========================================================================
// src/encoding/bech32.rs
// ==========================================================================

// Allow unsafe_code when zeroize is enabled (needed for bech32 string validation)
// but forbid it otherwise
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

use alloc::string::String;
use bech32::{Bech32, Hrp};

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

/// Validated, Bech32 string wrapper for secret data like age keys.
///
/// This struct ensures the contained string is valid Bech32 encoding.
/// Provides methods for decoding back to bytes.
///
/// Supports age-relevant HRPs: "age", "age1pq", "age-secret-key-1", "age-secret-key-pq-".
/// Accepts uppercase input (as from age/rage), normalizes to lowercase.
///
pub struct Bech32String(crate::Dynamic<String>);

impl Bech32String {
    /// Create a new `Bech32String` from a `String`, validating it as Bech32.
    ///
    /// The input `String` is consumed. If validation fails and the `zeroize` feature
    /// is enabled, the rejected bytes are zeroized before the error is returned.
    ///
    /// Validation rules:
    /// - Valid Bech32 checksum and character set via `bech32::decode`
    /// - Accepts uppercase (normalized to lowercase)
    /// - Restricted to age-relevant HRPs: "age", "age1pq", "age-secret-key-1", "age-secret-key-pq-"
    ///
    /// # Errors
    ///
    /// Returns `Err("invalid bech32 string")` if validation fails.
    /// Supports age-relevant HRPs: "age", "age1pq", "age-secret-key-1", "age-secret-key-pq-".
    /// Accepts uppercase input (as from age/rage), normalizes to lowercase.
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        // Attempt to decode with bech32
        match bech32::decode(&s) {
            Ok((hrp, data)) => {
                // Check against allowed HRPs
                if matches!(hrp.as_str(), "age" | "age1pq" | "age-secret-key-1" | "age-secret-key-pq-") {
                    // Normalize to lowercase
                    let normalized = bech32::encode::<Bech32>(hrp, &data).expect("re-encoding valid bech32 should succeed");
                    Ok(Self(crate::Dynamic::new(normalized)))
                } else {
                    zeroize_input(&mut s);
                    Err("invalid bech32 string")
                }
            }
            Err(_) => {
                zeroize_input(&mut s);
                Err("invalid bech32 string")
            }
        }
    }

    /// Internal constructor for trusted Bech32 strings (e.g., from validated sources).
    ///
    /// Skips validation – caller must ensure the string is valid Bech32 with allowed HRP.
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(crate::Dynamic::new(s))
    }

    /// Decode the validated Bech32 string back into raw bytes (5-to-8 bit conversion).
    ///
    /// Panics if the internal string is somehow invalid (impossible under correct usage).
    pub fn to_bytes(&self) -> Vec<u8> {
        let (_, data) = bech32::decode(self.0.expose_secret()).expect("Bech32String is always valid");
        data
    }

    /// Number of bytes the decoded Bech32 string represents.
    pub fn byte_len(&self) -> usize {
        self.to_bytes().len()
    }

    /// The Human-Readable Part of the Bech32 string.
    pub fn hrp(&self) -> Hrp {
        bech32::decode(self.0.expose_secret()).expect("Bech32String is always valid").0
    }

    /// Whether this Bech32 string is for a post-quantum age key (PQ variant).
    pub fn is_postquantum(&self) -> bool {
        matches!(self.hrp().as_str(), "age1pq" | "age-secret-key-pq-")
    }

    /// Primary way to access the validated string — returns &String for consistency
    #[inline(always)]
    pub const fn expose_secret(&self) -> &String {
        self.0.expose_secret()
    }

    /// Length of the encoded string (in characters) — delegate directly
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the encoded string is empty — delegate directly
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Constant-time equality for bech32 strings – prevents timing attacks when ct-eq enabled
#[cfg(all(feature = "encoding-bech32", feature = "ct-eq"))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        use crate::eq::ConstantTimeEq;
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(all(feature = "encoding-bech32", not(feature = "ct-eq")))]
impl PartialEq for Bech32String {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[cfg(feature = "encoding-bech32")]
impl Eq for Bech32String {}

impl core::fmt::Debug for Bech32String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
