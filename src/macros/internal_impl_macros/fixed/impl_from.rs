//! Internal macros for From implementations in secure-gate types.
//!
//! This module contains macros used to implement From traits
//! for Fixed types without code duplication.

/// Macro to implement From traits for Fixed types.
///
/// This generates various From impls for Fixed, such as from arrays.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_fixed {
    (array) => {
        impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
            /// Wrap a raw byte array in a `Fixed` secret.
            ///
            /// Zero-cost conversion.
            ///
            /// # Example
            ///
            /// ```
            /// use secure_gate::Fixed;
            /// let key: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
            /// ```
            #[inline(always)]
            fn from(arr: [u8; N]) -> Self {
                Self::new(arr)
            }
        }
    };
}
