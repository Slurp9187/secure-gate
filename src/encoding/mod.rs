//! Encoding utilities for secure handling of encoded secret data.
//!
//! This module provides validated string wrappers for various encoding formats
//! commonly used with cryptographic secrets. Each wrapper ensures the contained
//! string is valid for its encoding format and provides secure decoding methods.
//!
//! The wrappers are designed to prevent accidental leakage of sensitive data:
//! - Input validation with secure zeroization of invalid inputs
//! - Controlled access to decoded bytes through explicit methods
//! - Constant-time equality comparison (when `ct-eq` feature is enabled)
//! - Debug redaction to prevent accidental logging of secrets
//!
//! # Available Encodings
//!
//! - **Hex**: Lowercase hexadecimal strings via `hex` module
//! - **Base64**: URL-safe base64 (no padding) via `base64` module
//! - **Bech32/Bech32m**: Human-readable encoded strings via `bech32` module
//!
//! # Security Features
//!
//! All encoding wrappers implement secure practices:
//! - **Security**: Invalid inputs are only zeroized when the `zeroize` feature is enabled.
//! Without `zeroize`, rejected secrets may remain in memory until normal drop.
//! - Constant-time equality prevents timing attacks (with `ct-eq`)
//! - Memory is securely zeroized when wrappers are dropped
//! - Debug output shows `[REDACTED]` to prevent accidental exposure

#![cfg_attr(
    not(any(
        feature = "encoding-hex",
        feature = "encoding-base64",
        feature = "encoding-bech32"
    )),
    forbid(unsafe_code)
)]

#[cfg(feature = "encoding-hex")]
pub mod hex;
#[cfg(feature = "encoding-hex")]
pub mod hex_random_ext;

#[cfg(feature = "encoding-base64")]
pub mod base64;
#[cfg(feature = "encoding-base64")]
pub mod base64_random_ext;

#[cfg(feature = "encoding-bech32")]
pub mod bech32;
#[cfg(feature = "encoding-bech32")]
pub mod bech32_random_ext;
