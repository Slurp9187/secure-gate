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
/// use secure_gate::CloneableType;
///
/// #[derive(Clone)]
/// struct MySecret(Vec<u8>);
///
/// impl CloneableType for MySecret {}
///
/// // Now MySecret can be safely cloned as it's marked with CloneableType
/// ```
#[allow(dead_code)]
pub trait CloneableType {}
