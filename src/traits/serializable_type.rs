//! Marker trait for opt-in serialization of raw secrets.

//! Marker trait for types allowing secure serialization.
//!
//! Implement this on types that can be deliberately serialized while maintaining security.
//! The trait itself is a marker and does not provide methods, but implementations must
//! ensure that serialization does not leak secrets unintentionally.

#[allow(dead_code)]
pub trait SerializableType {}
