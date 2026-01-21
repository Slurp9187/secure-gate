//! Internal macros for constant-time equality in secure-gate types.
//!
//! This module contains macros used to implement ct_eq methods
//! for Dynamic types without code duplication.

/// Macro to implement constant-time equality for Dynamic types.
///
/// This generates a ct_eq method that compares byte contents in constant time.
/// Requires the "ct-eq" feature.
#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_ct_eq_dynamic {
    ($type:ty, $method:ident) => {
        #[cfg(feature = "ct-eq")]
        impl $type {
            /// Constant-time equality comparison.
            ///
            /// Compares the byte contents of two instances in constant time
            /// to prevent timing attacks.
            #[inline]
            pub fn ct_eq(&self, other: &Self) -> bool {
                use $crate::traits::ConstantTimeEq;
                self.inner.$method().ct_eq(other.inner.$method())
            }
        }
    };
}
