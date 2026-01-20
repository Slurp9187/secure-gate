//! Internal macros for constant-time equality in secure-gate types.
//!
//! This module contains macros used to implement ct_eq methods
//! for Dynamic types without code duplication.

/// Macro to implement constant-time equality for Dynamic types.
///
/// This generates a ct_eq method that compares byte contents in constant time.
/// Requires the "ct-eq" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_ct_eq_dynamic {
    ($type:ty, $method:ident) => {
        #[cfg(feature = "ct-eq")]
        impl $type {
            /// Constant-time equality comparison.
            ///
            /// Compares the byte contents of two instances in constant time
            /// to prevent timing attacks.
            ///
            /// # Examples
            ///
            /// ```
            /// # #[cfg(feature = "ct-eq")]
            /// # {
            /// use secure_gate::Dynamic;
            /// let a = Dynamic::new(/* ... */);
            /// let b = Dynamic::new(/* ... */);
            /// assert!(a.ct_eq(&b));
            /// # }
            /// ```
            #[inline]
            pub fn ct_eq(&self, other: &Self) -> bool {
                use crate::traits::ConstantTimeEq;
                self.inner.$method().ct_eq(other.inner.$method())
            }
        }
    };
}

/// Macro to implement constant-time equality for Fixed byte array types.
///
/// This generates a ct_eq method for Fixed<[u8; N]> that compares in constant time.
/// Requires the "ct-eq" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_ct_eq_fixed {
    () => {
        #[cfg(feature = "ct-eq")]
        impl<const N: usize> Fixed<[u8; N]> {
            /// Constant-time equality comparison.
            ///
            /// This is the **only safe way** to compare two fixed-size secrets.
            /// Available only when the `ct-eq` feature is enabled.
            ///
            /// # Example
            ///
            /// ```
            /// # #[cfg(feature = "ct-eq")]
            /// # {
            /// use secure_gate::Fixed;
            /// let a = Fixed::new([1u8; 32]);
            /// let b = Fixed::new([1u8; 32]);
            /// assert!(a.ct_eq(&b));
            /// # }
            /// ```
            #[inline]
            pub fn ct_eq(&self, other: &Self) -> bool {
                use crate::traits::ConstantTimeEq;
                self.inner.ct_eq(&other.inner)
            }
        }
    };
}
