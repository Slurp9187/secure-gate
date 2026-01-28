//! Marker trait for opt-in serialization of raw secrets.

/// Implement this on types that can be deliberately serialized while maintaining security.
/// The trait itself is a marker and does not provide methods, but implementations must
/// ensure that serialization does not leak secrets unintentionally.
///
/// # Examples
///
/// ```rust
/// # #[cfg(feature = "serde-serialize")]
/// # {
/// use secure_gate::SerializableSecret;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MySecret {
///     data: Vec<u8>,
/// }
///
/// impl SerializableSecret for MySecret {}
///
/// // Now MySecret can be serialized securely, as it's marked with SerializableSecret
/// # }
/// ```
#[cfg(feature = "serde-serialize")]
pub trait SerializableSecret: serde::Serialize {}
