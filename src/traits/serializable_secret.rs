//! Marker trait for types that allow secure serialization of secrets.
//!
//! This module defines the [`SerializableSecret`] trait and provides
//! blanket implementations for primitive types and fixed-size arrays that are safe to
//! serialize when handling sensitive data. The trait ensures that only types meeting the
//! security requirements are allowed opt-in serialization.
//!
//! ## Security Warning
//!
//! **Implementing this trait allows serialization of secret data, which can lead to
//! permanent exposure if not handled carefully. Only implement for types where
//! serialization is absolutely necessary and under controlled conditions.**
//!
//! Serialization of secrets should be:
//! - Limited to secure, trusted contexts (e.g., config files, not network transmission)
//! - Followed by immediate zeroization of the serialized form
//! - Restricted to types with short lifetimes or fixed sizes
//!
//! # Safety
//
//! This trait is intentionally restrictive and opt-in. Only implement it for types where
//! serialization won't compromise security. Safe examples include primitives and small,
//! fixed-size arrays in trusted environments. Avoid implementing for large or complex
//! types that could leak sensitive data.
//!
//! **Security Note**: Grep for `impl SerializableSecret` during code reviews – each
//! implementation is a potential exfiltration point.
//!
//! This trait is re-exported at the crate root when the `serde` feature is enabled.
//!
//! # Examples
//!
//! Implement for a custom secret type (use with extreme caution):
//! ```
//! # #[cfg(feature = "serde")]
//! # {
//! use secure_gate::SerializableSecret;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct MySecret([u8; 32]);
//!
//! impl SerializableSecret for MySecret {}
//! # }
//! ```
pub trait SerializableSecret: serde::Serialize {
    // Pure marker, no methods
}

// No blanket implementations - serialization is purely opt-in.
// Users must explicitly implement SerializableSecret for types they want to serialize.
// This prevents accidental exfiltration of secrets via serde.
