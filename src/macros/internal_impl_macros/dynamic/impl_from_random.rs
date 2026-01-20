//! Internal macros for random generation in secure-gate types.
//!
//! This module contains macros used to implement from_random methods
//! for Dynamic types without code duplication.

/// Macro to implement from_random for Dynamic byte vectors.
///
/// This generates a from_random method that fills a Vec<u8> with random bytes.
/// Requires the "rand" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_random_dynamic {
    ($type:ty) => {
        /// Random generation — only available with `rand` feature.
        #[cfg(feature = "rand")]
        impl $type {
            /// Fill with fresh random bytes of the specified length using the OS RNG.
            ///
            /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
            /// from system sources.
            ///
            /// # Example
            ///
            /// ```
            /// # #[cfg(feature = "rand")]
            /// # {
            /// use secure_gate::{Dynamic, ExposeSecret};
            /// let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
            /// assert_eq!(random.len(), 64);
            /// # }
            /// ```
            #[inline]
            pub fn from_random(len: usize) -> Self {
                let mut bytes = Vec::with_capacity(len);
                bytes.resize(len, 0u8);
                rand::rngs::OsRng
                    .try_fill_bytes(&mut bytes)
                    .expect("OsRng failure is a program error");
                Self::from(bytes)
            }
        }
    };
}
