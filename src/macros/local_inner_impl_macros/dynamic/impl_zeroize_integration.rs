/// Macro to implement zeroize integration for Dynamic-like secret wrapper types.
///
/// This ensures that Dynamic types can be securely zeroed when the inner type supports Zeroize.
/// Requires the "zeroize" feature.
#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_zeroize_integration_dynamic {
    ($type:ty) => {
        /// Zeroize integration.
        #[cfg(feature = "zeroize")]
        impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for $type {
            fn zeroize(&mut self) {
                self.inner.zeroize();
            }
        }

        /// Zeroize on drop integration.
        #[cfg(feature = "zeroize")]
        impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for $type {}
    };
}
