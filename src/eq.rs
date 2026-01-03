// ==========================================================================
// src/eq.rs
// ==========================================================================

#[cfg(feature = "ct-eq")]
/// Trait for constant-time equality comparison to prevent timing attacks.
///
/// Implemented for byte arrays and slices. Uses `subtle` crate for secure comparison.
///
/// # Examples
///
/// ```
/// # use secure_gate::eq::ConstantTimeEq;
/// let a = [1u8, 2u8];
/// let b = [1u8, 2u8];
/// assert!(a.ct_eq(&b));
/// ```
pub trait ConstantTimeEq {
    /// Compare two values in constant time.
    ///
    /// Returns `true` if they are equal, `false` otherwise.
    /// Safe against timing attacks.
    fn ct_eq(&self, other: &Self) -> bool;
}

#[cfg(feature = "ct-eq")]
impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(self, other).into()
    }
}

#[cfg(feature = "ct-eq")]
impl<const N: usize> ConstantTimeEq for [u8; N] {
    fn ct_eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice())
    }
}
