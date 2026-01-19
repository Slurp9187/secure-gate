// Allow unsafe_code when zeroize is enabled (needed for hex string validation)
// but forbid it otherwise
#![cfg_attr(not(feature = "zeroize"), forbid(unsafe_code))]

use alloc::string::String;
use hex as hex_crate;

use crate::traits::expose_secret::ExposeSecret;

#[cfg(feature = "serde-deserialize")]
use serde::Deserialize;

#[cfg(feature = "serde-serialize")]
use serde::{ser::Serializer, Serialize};

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
/// # use secure_gate::{encoding::hex::HexString, ExposeSecret};
/// let valid = HexString::new("deadbeef".to_string()).unwrap();
/// assert_eq!(valid.expose_secret(), "deadbeef");
/// let bytes = valid.decode_into_bytes(); // Vec<u8> of [0xde, 0xad, 0xbe, 0xef]
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
    /// use secure_gate::{encoding::hex::HexString, ExposeSecret};
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

    /// Number of bytes the decoded hex string represents.
    pub fn byte_len(&self) -> usize {
        self.0.expose_secret().len() / 2
    }

    /// decode_to_bytes: borrowing, allocates fresh ` from decoded bytes
    pub fn decode_to_bytes(&self) -> Vec<u8> {
        hex_crate::decode(self.expose_secret()).expect("HexString invariant: always valid")
    }

    /// decode_into_bytes: consuming, decodes then zeroizes the wrapper immediately
    pub fn decode_into_bytes(self) -> Vec<u8> {
        hex_crate::decode(self.expose_secret()).expect("HexString invariant: always valid")
    }
}

/// Constant-time equality for hex strings — prevents timing attacks when `ct-eq` feature is enabled.
#[cfg(feature = "ct-eq")]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.0
            .expose_secret()
            .as_bytes()
            .ct_eq(other.0.expose_secret().as_bytes())
    }
}

#[cfg(not(feature = "ct-eq"))]
impl PartialEq for HexString {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

/// Equality implementation for hex strings.
impl Eq for HexString {}

/// Debug implementation (always redacted).
impl core::fmt::Debug for HexString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Serde deserialization support (validates on deserialization).
#[cfg(feature = "serde-deserialize")]
impl<'de> Deserialize<'de> for HexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// Serde serialization support (serializes the hex string).
/// Uniformly gated by SerializableSecret marker.
/// Users must implement SerializableSecret to enable serialization.
#[cfg(feature = "serde-serialize")]
impl Serialize for HexString
where
    String: crate::SerializableSecret,  // User must impl on String
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose_secret().serialize(serializer)  // String output
    }
}
