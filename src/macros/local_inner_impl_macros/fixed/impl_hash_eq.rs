//! Internal macros for hash-based equality in secure-gate types.
//!
//! This module contains macros used to implement hash equality traits
//! for Fixed types without code duplication.

/// Macro to implement hash equality for Fixed types.
///
/// This generates PartialEq, Eq, and Hash impls with inlined hash computation for Fixed types.
/// Requires the "hash-eq" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_hash_eq_fixed {
    () => {
        #[cfg(feature = "hash-eq")]
        impl<T: AsRef<[u8]>> PartialEq for Fixed<T> {
            fn eq(&self, other: &Self) -> bool {
                use blake3::hash;
                use $crate::traits::ConstantTimeEq;
                let self_hash = *hash(self.inner.as_ref()).as_bytes();
                let other_hash = *hash(other.inner.as_ref()).as_bytes();
                self_hash.ct_eq(&other_hash)
            }
        }

        #[cfg(feature = "hash-eq")]
        impl<T: AsRef<[u8]>> Eq for Fixed<T> {}

        #[cfg(feature = "hash-eq")]
        impl<T: AsRef<[u8]>> core::hash::Hash for Fixed<T> {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                use blake3::hash;
                let hash_bytes = *hash(self.inner.as_ref()).as_bytes();
                hash_bytes.hash(state);
            }
        }
    };
}
