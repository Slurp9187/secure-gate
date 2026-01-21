//! Internal macros for hash-based equality in secure-gate types.
//!
//! This module contains macros used to implement hash equality traits
//! for Dynamic types without code duplication.

/// Macro to implement hash equality for Dynamic types.
///
/// This generates PartialEq, Eq, and Hash impls with inlined hash computation for specific Dynamic types.
/// Requires the "hash-eq" feature.
#[doc(hidden)]
#[macro_export(local_inner_macros)]
macro_rules! impl_hash_eq_dynamic {
    ($inner:ty, $method:ident) => {
        #[cfg(feature = "hash-eq")]
        impl PartialEq for Dynamic<$inner> {
            fn eq(&self, other: &Self) -> bool {
                use blake3::hash;
                use $crate::traits::ConstantTimeEq;
                let self_hash = *hash(self.inner.$method()).as_bytes();
                let other_hash = *hash(other.inner.$method()).as_bytes();
                self_hash.ct_eq(&other_hash)
            }
        }

        #[cfg(feature = "hash-eq")]
        impl Eq for Dynamic<$inner> {}

        #[cfg(feature = "hash-eq")]
        impl core::hash::Hash for Dynamic<$inner> {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                use blake3::hash;
                let hash_bytes = *hash(self.inner.$method()).as_bytes();
                hash_bytes.hash(state);
            }
        }
    };
}
