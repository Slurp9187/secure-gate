//! Internal macros for random generation in secure-gate types.
//!
//! This module contains macros used to implement from_random methods
//! for Fixed types without code duplication.

/// Macro to implement from_random for Fixed byte arrays.
///
/// This generates a from_random method that creates a random [u8; N] filled with random bytes.
/// Requires the "rand" feature.
#[macro_export(local_inner_macros)]
macro_rules! impl_from_random_fixed {
    () => {
        /// Random generation — only available with `rand` feature.
        #[cfg(feature = "rand")]
        impl<const N: usize> Fixed<[u8; N]> {
            /// Generate a secure random instance (panics on failure).
            ///
            /// Fill with fresh random bytes using the OS RNG.
            /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
            /// from system sources.
            ///
            /// # Example
            ///
            /// ```
            /// # #[cfg(feature = "rand")]
            /// # {
            /// use secure_gate::{Fixed, ExposeSecret};
            /// let random: Fixed<[u8; 32]> = Fixed::from_random();
            /// assert_eq!(random.len(), 32);
            /// # }
            /// ```
            #[inline]
            pub fn from_random() -> Self {
                let mut bytes = [0u8; N];
                rand::rngs::OsRng
                    .try_fill_bytes(&mut bytes)
                    .expect("OsRng failure is a program error");
                Self::from(bytes)
            }
        }
    };
}
