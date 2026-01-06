// ==========================================================================
// src/encoding/base64.rs
// ==========================================================================

// but forbid it otherwise
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
use alloc::string::String;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

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

/// Validated, URL-safe base64 string wrapper for secret data (no padding).
///
/// This struct ensures the contained string is valid URL-safe base64.
/// Provides methods for decoding back to bytes.
///
/// # Examples
///
/// ```
/// # use secure_gate::encoding::base64::Base64String;
/// let valid = Base64String::new("SGVsbG8".to_string()).unwrap();
/// assert_eq!(valid.expose_secret(), "SGVsbG8");
/// let bytes = valid.into_bytes(); // Vec<u8> of "Hello"
/// ```
pub struct Base64String(pub(crate) crate::Dynamic<String>);

impl Base64String {
    /// Create a new `Base64String` from a `String`, validating it as URL-safe base64 (no padding).
    ///
    /// The input `String` is consumed. If validation fails and the `zeroize` feature
    /// is enabled, the rejected bytes are zeroized before the error is returned.
    ///
    /// Validation rules:
    /// - Valid URL-safe base64 characters (A-Z, a-z, 0-9, -, _)
    /// - No padding ('=' not allowed, as we use no-pad)
    /// - Must be decodable as valid base64 (prevents `to_bytes()` panics)
    ///
    /// # Errors
    ///
    /// Returns `Err("invalid base64 string")` if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "encoding-base64")]
    /// # {
    /// use secure_gate::encoding::base64::Base64String;
    /// let valid = Base64String::new("SGVsbG8".to_string()).unwrap();
    /// assert_eq!(valid.expose_secret(), "SGVsbG8");
    /// let bytes = valid.into_bytes(); // Vec<u8> of "Hello"
    /// # }
    /// ```
    pub fn new(s: String) -> Result<Self, &'static str> {
        if URL_SAFE_NO_PAD.decode(&s).is_ok() {
            Ok(Self(crate::Dynamic::new(s)))
        } else {
            let mut s = s;
            zeroize_input(&mut s);
            Err("invalid base64 string")
        }
    }

    /// Internal constructor for trusted base64 strings (e.g., from RNG).
    ///
    /// Skips validation – caller must ensure the string is valid base64.
    #[allow(dead_code)]
    pub(crate) fn new_unchecked(s: String) -> Self {
        Self(crate::Dynamic::new(s))
    }

    /// Exact number of bytes the decoded base64 string represents.
    #[inline(always)]
    pub fn byte_len(&self) -> usize {
        let len = self.len();
        (len / 4) * 3 + (len % 4 == 2) as usize + (len % 4 == 3) as usize * 2
    }

    /// Length of the encoded string (in characters).
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the encoded string is empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// Constant-time equality for base64 strings – prevents timing attacks when ct-eq enabled
#[cfg(feature = "encoding-base64")]
impl PartialEq for Base64String {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "ct-eq")]
        {
            use crate::ct_eq::ConstantTimeEq;
            self.0
                .expose_secret()
                .as_bytes()
                .ct_eq(other.0.expose_secret().as_bytes())
        }
        #[cfg(not(feature = "ct-eq"))]
        {
            self.0.expose_secret() == other.0.expose_secret()
        }
    }
}

#[cfg(feature = "encoding-base64")]
impl Eq for Base64String {}

impl core::fmt::Debug for Base64String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
