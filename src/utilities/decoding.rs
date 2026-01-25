// secure-gate/src/utilities/decoding.rs
//! Multi-format decoding helpers for secure-gate.!
//! This module provides utilities for decoding strings that may be encoded in various formats.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Bech32,
    Bech32m,
    Hex,
    Base64Url,
}

// Default order: Bech32 → Hex → Base64Url
pub const DEFAULT_ORDER: &[Format] = &[Format::Bech32, Format::Hex, Format::Base64Url];

/// Attempt to decode a string in a configurable priority order.
///
/// Tries formats in the order specified by `priority`, or defaults to `DEFAULT_ORDER`
/// (Bech32 → Hex → Base64Url) if `None`. This allows strict protocols to restrict formats
/// (e.g., only Hex) or customize order for performance.
///
/// # Security Note
/// Use explicit priority when the expected format is known (e.g., protocol spec) to avoid ambiguous parsing or side-channel risks from auto-detection order.
///
/// # Examples
/// Default order (Bech32 → Hex → Base64Url):
/// ```
/// use secure_gate::utilities::decoding::try_decode_any;
/// let bytes = try_decode_any("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None)?;  // Tries Bech32 first
/// # Ok::<(), secure_gate::DecodingError>(())
/// ```
///
/// Strict Hex-only for API keys:
/// ```
/// use secure_gate::utilities::decoding::{try_decode_any, Format};
/// let bytes = try_decode_any("deadbeef", Some(&[Format::Hex]))?;
/// # Ok::<(), secure_gate::DecodingError>(())
/// ```
///
/// Custom order for multi-format protocol:
/// ```
/// use secure_gate::utilities::decoding::{try_decode_any, Format};
/// let bytes = try_decode_any("SGVsbG8=", Some(&[Format::Base64Url, Format::Hex]))?;
/// # Ok::<(), secure_gate::DecodingError>(())
/// ```
///
/// Returns `Ok(Vec<u8>)` on success or `Err(DecodingError)` if no format matches.
#[cfg(feature = "serde-deserialize")]
pub fn try_decode_any(
    s: &str,
    priority: Option<&[Format]>,
) -> Result<Vec<u8>, crate::DecodingError> {
    let order = priority.unwrap_or(DEFAULT_ORDER);
    let mut attempted = Vec::new();

    for &fmt in order {
        attempted.push(fmt);
        match fmt {
            #[cfg(feature = "encoding-bech32")]
            Format::Bech32 => {
                use super::conversion::fes_to_u8s;
                use ::bech32;
                if let Ok((_, data)) = bech32::decode(s) {
                    return Ok(fes_to_u8s(data));
                }
            }
            #[cfg(feature = "encoding-hex")]
            Format::Hex => {
                if let Ok(data) = ::hex::decode(s) {
                    return Ok(data);
                }
            }
            #[cfg(feature = "encoding-base64")]
            Format::Base64Url => {
                use ::base64::engine::general_purpose::URL_SAFE;
                use ::base64::Engine as _;
                if let Ok(data) = URL_SAFE.decode(s) {
                    return Ok(data);
                }
            }
            _ => {} // Skip unsupported formats (e.g., if feature not enabled)
        }
    }

    let hint = format!(
        "string does not match any supported format. Attempted order: {:?}",
        attempted
    );
    Err(crate::DecodingError::InvalidEncoding { hint })
}
