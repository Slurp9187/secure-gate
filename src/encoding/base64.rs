// Forbid unsafe_code when the "zeroize" feature is disabled, to ensure secure handling
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]
use alloc::string::String;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "hash-eq")]
use blake3::hash;

use base64::Engine;

#[cfg(feature = "serde-deserialize")]
use serde::Deserialize;

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

/// Validated, URL-safe base64 string wrapper for secret data (no padding).
///
/// This struct ensures the contained string is valid URL-safe base64.
/// Provides methods for decoding back to bytes.
///
/// # Examples
///
/// ```
/// # use secure_gate::{encoding::base64::Base64String, ExposeSecret};
/// let valid = Base64String::new("SGVsbG8".to_string()).unwrap();
/// assert_eq!(valid.expose_secret(), "SGVsbG8");
/// let bytes = valid.decode_into_bytes(); // Vec<u8> of "Hello"
/// ```
pub struct Base64String(pub(crate) crate::Dynamic<String>);

impl Base64String {
    /// Create a new `Base64String` from a `String`, validating it as URL-safe base64 (no padding).
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
    /// use secure_gate::{encoding::base64::Base64String, ExposeSecret};
    /// let valid = Base64String::new("SGVsbG8".to_string()).unwrap();
    /// assert_eq!(valid.expose_secret(), "SGVsbG8");
    /// let bytes = valid.decode_into_bytes(); // Vec<u8> of "Hello"
    /// # }
    /// ```
    pub fn new(s: String) -> Result<Self, &'static str> {
        if URL_SAFE_NO_PAD.decode(&s).is_ok() {
            #[allow(unused_mut)]
            let mut result = Self(crate::Dynamic::new(s));
            #[cfg(feature = "hash-eq")]
            {
                result.0.eq_hash = *hash(result.0.expose_secret().as_bytes()).as_bytes();
            }
            Ok(result)
        } else {
            let mut s = s;
            zeroize_input(&mut s);
            Err("invalid base64 string")
        }
    }

    /// Exact number of bytes the decoded base64 string represents.
    #[inline(always)]
    pub fn byte_len(&self) -> usize {
        let len = self.0.len();
        (len * 3) / 4
    }

    /// decode_to_bytes: borrowing, allocates fresh `Vec<u8>` from decoded bytes
    pub fn decode_to_bytes(&self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.expose_secret())
            .expect("Base64String invariant: always valid")
    }

    /// decode_into_bytes: consuming, decodes then zeroizes the wrapper immediately
    pub fn decode_into_bytes(self) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(self.expose_secret())
            .expect("Base64String invariant: always valid")
    }
}

// Equality for base64 strings – uses hash-eq when enabled, else ct-eq or string comparison
impl PartialEq for Base64String {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "hash-eq")]
        {
            use crate::ConstantTimeEq;
            self.0.eq_hash.ct_eq(&other.0.eq_hash).into()
        }
        #[cfg(not(feature = "hash-eq"))]
        {
            #[cfg(feature = "ct-eq")]
            {
                use crate::traits::ConstantTimeEq;
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
}

impl Eq for Base64String {}

/// Debug implementation (always redacted).
impl core::fmt::Debug for Base64String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Serde deserialization support (validates on deserialization).
#[cfg(feature = "serde-deserialize")]
impl<'de> Deserialize<'de> for Base64String {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde-serialize")]
impl From<Base64String> for crate::ExportableString {
    fn from(value: Base64String) -> Self {
        let s = value.expose_secret().to_string();
        Self::from(s)
    }
}

#[cfg(feature = "serde-serialize")]
impl From<Base64String> for crate::ExportableVec {
    fn from(value: Base64String) -> Self {
        let vec = value.decode_into_bytes();
        Self::from(vec)
    }
}
