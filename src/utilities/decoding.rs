// secure-gate/src/utilities/decoding.rs
//! Multi-format decoding helpers for secure-gate.
//!
//! This module provides utilities for decoding strings that may be encoded in various formats.

#[cfg(feature = "encoding-bech32")]
use super::encoding::fes_to_u8s;

/// Attempt to decode a string in priority order: Bech32 → Bech32m → Hex → Base64url.
///
/// Returns `Ok(Vec<u8>)` on success or `Err(DecodingError)` if no format matches.
#[cfg(feature = "serde-deserialize")]
pub fn try_decode_any(s: &str) -> Result<Vec<u8>, crate::DecodingError> {
    #[cfg(feature = "encoding-bech32")]
    {
        use ::bech32;
        // Try Bech32 first (bech32::decode prioritizes Bech32 over Bech32m)
        if let Ok((_, data)) = bech32::decode(s) {
            return Ok(fes_to_u8s(data));
        }
    }

    #[cfg(feature = "encoding-hex")]
    if let Ok(data) = ::hex::decode(s) {
        return Ok(data);
    }

    #[cfg(feature = "encoding-base64")]
    {
        use ::base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ::base64::Engine as _;
        if let Ok(data) = URL_SAFE_NO_PAD.decode(s) {
            return Ok(data);
        }
    }

    Err(crate::DecodingError::InvalidEncoding)
}
