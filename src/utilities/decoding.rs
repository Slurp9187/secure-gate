// secure-gate/src/utilities/decoding.rs
//! Multi-format decoding helpers for secure-gate.!
//! This module provides utilities for decoding strings that may be encoded in various formats.

#[cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    feature = "encoding-hex",
    feature = "encoding-base64"
))]
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(docsrs, doc(cfg(feature = "encoding-bech32")))]
#[cfg(feature = "encoding-bech32")]
pub enum Format {
    #[cfg_attr(docsrs, doc(cfg(feature = "encoding-bech32")))]
    #[cfg(feature = "encoding-bech32")]
    Bech32,
    #[cfg_attr(docsrs, doc(cfg(feature = "encoding-bech32m")))]
    #[cfg(feature = "encoding-bech32m")]
    Bech32m,
    #[cfg_attr(docsrs, doc(cfg(feature = "encoding-hex")))]
    #[cfg(feature = "encoding-hex")]
    Hex,
    #[cfg_attr(docsrs, doc(cfg(feature = "encoding-base64")))]
    #[cfg(feature = "encoding-base64")]
    Base64Url,
}

#[cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    feature = "encoding-hex",
    feature = "encoding-base64"
))]
pub fn default_order() -> Vec<Format> {
    [
        #[cfg(feature = "encoding-bech32")]
        Some(Format::Bech32),
        #[cfg(feature = "encoding-hex")]
        Some(Format::Hex),
        #[cfg(feature = "encoding-base64")]
        Some(Format::Base64Url),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Attempt to decode a string in a configurable priority order.
///
/// Tries formats in the order specified by `priority`, or defaults to the default order
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
/// let bytes = try_decode_any("deadbeef", Some(&[Format::Bech32, Format::Hex]))?;
/// # Ok::<(), secure_gate::DecodingError>(())
/// ```
///
/// Returns `Ok(Vec<u8>)` on success or `Err(DecodingError)` if no format matches.
#[cfg(feature = "serde-deserialize")]
#[cfg(any(
    feature = "encoding-bech32",
    feature = "encoding-bech32m",
    feature = "encoding-hex",
    feature = "encoding-base64"
))]
pub fn try_decode_any(
    s: &str,
    priority: Option<&[Format]>,
) -> Result<Vec<u8>, crate::DecodingError> {
    let order = priority.map(|p| p.to_vec()).unwrap_or_else(default_order);
    let attempted: Vec<Format> = order.clone();
    for fmt in attempted.iter() {
        match fmt {
            #[cfg(feature = "encoding-bech32")]
            Format::Bech32 => {
                use super::conversion::fes_to_u8s;
                use ::bech32;
                if let Ok((_, data)) = bech32::decode(s) {
                    return Ok(fes_to_u8s(data));
                }
            }
            #[cfg(feature = "encoding-bech32m")]
            Format::Bech32m => {
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
            #[cfg(not(any(
                feature = "encoding-bech32",
                feature = "encoding-bech32m",
                feature = "encoding-hex",
                feature = "encoding-base64"
            )))]
            _ => unreachable!("No encoding features enabled"),
        }
    }

    let hint = format!(
        "string does not match any supported format. Attempted order: {:?}",
        attempted
    );
    Err(crate::DecodingError::InvalidEncoding { hint })
}
