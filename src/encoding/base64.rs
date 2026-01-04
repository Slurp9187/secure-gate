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
/// let bytes = valid.to_bytes(); // Vec<u8> of "Hello"
/// ```
pub struct Base64String(crate::Dynamic<String>);

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
    /// # }
    /// ```
    pub fn new(mut s: String) -> Result<Self, &'static str> {
        // Validate in-place: check for invalid chars and that it can actually be decoded
        let bytes = s.as_bytes();
        let mut valid = true;

        // Check character validity
        for &b in bytes.iter() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {}
                _ => valid = false,
            }
        }

        // If characters are valid, verify it can actually be decoded (prevents to_bytes() panics)
        if valid {
            // Try decoding to ensure it's valid - this catches length/content issues
            if URL_SAFE_NO_PAD.decode(&s).is_err() {
                valid = false;
            }
        }

        if valid {
            Ok(Self(crate::Dynamic::new(s)))
        } else {
            zeroize_input(&mut s);
            Err("invalid base64 string")
        }
    }

    /// Decode the validated base64 string back into raw bytes.
    ///
    /// Panics if the internal string is somehow invalid (impossible under correct usage).
    pub fn to_bytes(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.0.expose_secret())
            .expect("Base64String is always valid")
    }

    /// Exact number of bytes the decoded base64 string represents.
    #[inline(always)]
    pub fn byte_len(&self) -> usize {
        let len = self.0.expose_secret().len();
        let full_groups = len / 4;
        let rem = len % 4;
        full_groups * 3
            + match rem {
                0 => 0,
                2 => 1,
                3 => 2,
                // rem == 1 is impossible due to Base64String validation
                // (no-pad base64 cannot represent 1 extra byte cleanly)
                1 => 0, // unreachable due to validation
                _ => 0, // other values impossible for len % 4
            }
    }

    /// Primary way to access the validated string.
    #[inline(always)]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret().as_str()
    }

    /// Length of the encoded string (in characters).
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// Whether the encoded string is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }
}

// Constant-time equality for base64 strings – prevents timing attacks when ct-eq enabled
#[cfg(all(feature = "encoding-base64", feature = "ct-eq"))]
impl PartialEq for Base64String {
    fn eq(&self, other: &Self) -> bool {
        use crate::eq::ConstantTimeEq;
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(all(feature = "encoding-base64", feature = "ct-eq"))]
impl Eq for Base64String {}

// Fallback: Standard string equality when ct-eq not enabled (secure enough for validation)
#[cfg(all(feature = "encoding-base64", not(feature = "ct-eq")))]
impl PartialEq for Base64String {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

#[cfg(all(feature = "encoding-base64", not(feature = "ct-eq")))]
impl Eq for Base64String {}

impl core::fmt::Debug for Base64String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
