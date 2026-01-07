// ==========================================================================
// src/encoding/hex.rs
// ==========================================================================

// Allow unsafe_code when zeroize is enabled (needed for hex string validation)
// but forbid it otherwise
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

use alloc::string::String;

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

/// Validated, lowercase hex string wrapper for secret data.
///
/// This struct ensures the contained string is valid hex (even length, valid chars).
/// Provides methods for decoding back to bytes.
///
/// The string is normalized to lowercase during validation.
///
/// # Examples
///
/// ```
/// # use secure_gate::encoding::hex::HexString;
/// let valid = HexString::new("deadbeef".to_string()).unwrap();
/// assert_eq!(valid.expose_secret(), "deadbeef");
/// let bytes = valid.into_bytes(); // Vec<u8> of [0xde, 0xad, 0xbe, 0xef]
/// ```
pub struct HexString(pub(crate) crate::Dynamic<String>);

impl HexString {
    /// Create a new `HexString` from a `String`, validating it in-place.
    ///
    /// The input `String` is consumed.
    ///
    /// # Security Note
    ///
    /// **Invalid inputs are only securely zeroized if the `zeroize` feature is enabled.**
    /// Without `zeroize`, rejected bytes may remain in memory until the `String` is dropped
    /// normally. Enable the `zeroize` feature for secure wiping of invalid inputs.
    ///
    /// Validation rules:
    /// - Even length
    /// - Only ASCII hex digits (`0-9`, `a-f`, `A-F`)
    /// - Uppercase letters are normalized to lowercase
    ///
    /// Zero extra allocations are performed – everything happens on the original buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err("invalid hex string")` if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::encoding::hex::HexString;
    /// let valid = HexString::new("deadbeef".to_string()).unwrap();
    /// assert_eq!(valid.expose_secret(), "deadbeef");
    /// ```
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        // Fast early check – hex strings must have even length
        if !s.len().is_multiple_of(2) {
            zeroize_input(&mut s);
            return Err("invalid hex string");
        }

        // Work directly on the underlying bytes – no copies
        let mut bytes = s.into_bytes();
        let mut valid = true;
        for b in &mut bytes {
            match *b {
                b'A'..=b'F' => *b += 32, // 'A' → 'a'
                b'a'..=b'f' | b'0'..=b'9' => {}
                _ => valid = false,
            }
        }

        if valid {
            s = String::from_utf8(bytes).expect("valid UTF-8 after hex normalization");
            Ok(Self(crate::Dynamic::new(s)))
        } else {
            s = String::from_utf8(bytes).unwrap_or_default();
            zeroize_input(&mut s);
            Err("invalid hex string")
        }
    }

    /// Internal constructor for trusted hex strings (e.g., from RNG).
    ///
    /// Skips validation – caller must ensure the string is valid lowercase hex.
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(crate::Dynamic::new(s))
    }

    /// Number of bytes the decoded hex string represents.
    pub fn byte_len(&self) -> usize {
        self.0.expose_secret().len() / 2
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

// Constant-time equality for hex strings – prevents timing attacks when ct-eq enabled
#[cfg(all(feature = "encoding-hex", feature = "ct-eq"))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(all(feature = "encoding-hex", not(feature = "ct-eq")))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[cfg(feature = "encoding-hex")]
impl Eq for HexString {}

impl core::fmt::Debug for HexString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
