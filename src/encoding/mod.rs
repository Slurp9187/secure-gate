//! Encoding utilities (gated behind “encoding” features).

// ==========================================================================
// src/encoding/mod.rs
// ==========================================================================

// Allow unsafe_code when zeroize is enabled (not needed here, but consistent)
// but forbid it when none of the encoding features are enabled
#![cfg_attr(
    not(any(feature = "encoding-hex", feature = "encoding-base64")),
    forbid(unsafe_code)
)]

#[cfg(feature = "encoding-hex")]
pub mod hex;

#[cfg(feature = "encoding-base64")]
pub mod base64;

#[cfg(feature = "encoding-bech32")]
pub mod bech32;

pub mod extensions;
