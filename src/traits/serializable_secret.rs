//! Marker trait for types that allow secure serialization of secrets.
//!
//! This module defines the [`SerializableSecret`] trait for opt-in serialization.
//! **No library implementations**—users must explicitly implement this for any type they wish to serialize.
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
//!
//! This trait is intentionally restrictive and opt-in. Only implement it for types where
//! serialization won't compromise security.
//!
//! **Security Note**: Grep for `impl SerializableSecret` during code reviews – each
//! implementation is a potential exfiltration point.
//!
//! This trait is re-exported at the crate root when the `serde-serialize` feature is enabled.
//!
//! # Examples
//!
//! Implement for a custom secret type (use with extreme caution):
//! ```
//! # #[cfg(feature = "serde-serialize")]
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
