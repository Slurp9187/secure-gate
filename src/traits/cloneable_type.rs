//! Marker trait for opt-in safe cloning with zeroization.

/// Marker trait for types that can be safely cloned with zeroization on drop.
///
/// Implement this trait on types that require safe duplication while maintaining
/// security guarantees. The trait itself is a marker and does not provide methods,
/// but implementations must ensure proper zeroization.
///
/// # Examples
///
/// ```rust
/// #[cfg(feature = "cloneable")]
/// {
///     use secure_gate::{CloneableType, Dynamic};
///
///     #[derive(Clone)]
///     struct MyKey([u8; 32]);
///
///     impl CloneableType for MyKey {}  // Opt-in to safe cloning
///
///     let key: Dynamic<MyKey> = MyKey([0; 32]).into();
///     let copy = key.clone();  // Now allowed, with zeroization on drop
/// }
/// ```
#[cfg(feature = "cloneable")]
pub trait CloneableType: Clone {}
