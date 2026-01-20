//! Encoding trait extensions for secure encoding of secret byte data to strings.
//!
//! This module provides the `SecureEncoding` trait for explicit, auditable encoding
//! of exposed bytes to human-readable strings (hex, base64, bech32). No wrappers—
//! just direct trait methods returning raw strings.
//!
//! Inbound decoding (e.g., `from_hex`) is handled by direct constructors on secret
//! types like `Fixed` and `Dynamic` for fail-fast behavior.
//!
//! # Available Encodings
//!
//! - **Hex**: Lowercase hexadecimal via `SecureEncoding::to_hex()`
//! - **Base64**: URL-safe base64 (no padding) via `SecureEncoding::to_base64url()`
//! - **Bech32/Bech32m**: Human-readable via `SecureEncoding::try_to_bech32()`
//!
//! # Security Features
//!
//! - All methods require `.expose_secret()` for auditability.
//! - `Debug` redaction prevents accidental logging.
//! - Fail-fast on invalid input via direct constructors.

//! (Empty module for future extensions if needed.)

// The `SecureEncoding` trait is defined in `src/traits/secure_encoding.rs`.
// No sub-modules remain after purging wrappers and extensions.
