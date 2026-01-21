//! Marker trait for opt-in serialization of raw secrets.
//
//! Marker trait for types allowing secure serialization.
//
//! Implement this on types that can be deliberately serialized while maintaining security.
//! The trait itself is a marker and does not provide methods, but implementations must
//! ensure that serialization does not leak secrets unintentionally.

/// Marker trait for opt-in serialization of raw secrets.
///
/// Marker trait for types allowing secure serialization.
///
/// Implement this on types that can be deliberately serialized while maintaining security.
/// The trait itself is a marker and does not provide methods, but implementations must
/// ensure that serialization does not leak secrets unintentionally.
///
/// # Examples
///
/// ```rust
/// use secure_gate::SerializableType;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MySecret {
///     data: Vec<u8>,
/// }
///
/// impl SerializableType for MySecret {}
///
/// // Now MySecret can be serialized securely, as it's marked with SerializableType
/// ```
#[allow(dead_code)]
pub trait SerializableType {}
