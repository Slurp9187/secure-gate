//! Internal macros for zeroize integration in secure-gate types.
//!
//! This module contains macros used to implement Zeroize and ZeroizeOnDrop traits
//! for Fixed types without code duplication.

/// Macro to implement zeroize integration for Fixed-like secret wrapper types.
///
/// This ensures that Fixed types can be securely zeroed when the inner type supports Zeroize.
/// Requires the "zeroize" feature.
#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_zeroize_integration_fixed {
    ($type:ty) => {
        /// Zeroize integration.
        #[cfg(feature = "zeroize")]
        impl<T: zeroize::Zeroize> zeroize::Zeroize for $type {
            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }

        /// Zeroize on drop integration.
        #[cfg(feature = "zeroize")]
        impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for $type {}
    };
}
