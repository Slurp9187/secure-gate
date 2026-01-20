//! # Mutable Secret Exposure Traits
//!
//! This module defines the trait for mutable access to secrets.
//!
//! ## Key Traits
//!
//! - [`ExposeSecretMut`]: Mutable access to secret values
//!
/// ## Usage
///
/// Import this trait to enable `.expose_secret_mut()` on mutable secret wrappers.
use super::ExposeSecret;
use crate::{Dynamic, Fixed};

/// Trait for mutable access to secrets.
///
/// Extends [`ExposeSecret`], so metadata and read access are included.
/// Import this for `.expose_secret_mut()`.
pub trait ExposeSecretMut: ExposeSecret {
    /// Expose the secret for mutable access.
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}

// ============================================================================
// Core Wrapper Implementations
// ============================================================================

/// Implementation for [`Fixed<[T; N]>`] - provides mutable access for arrays.
///
/// Extends the read-only implementation with mutation capabilities.
impl<const N: usize, T> ExposeSecretMut for Fixed<[T; N]> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

/// Implementation for [`Dynamic<String>`] - provides mutable access.
///
/// Extends the read-only implementation with mutation capabilities.
impl ExposeSecretMut for Dynamic<String> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut String {
        &mut self.inner
    }
}

/// Implementation for [`Dynamic<Vec<T>>`] - provides mutable access.
///
/// Extends the read-only implementation with mutation capabilities.
impl<T> ExposeSecretMut for Dynamic<Vec<T>> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }
}

// Implementation for [`Fixed<CloneableArrayInner<N>>`] - provides mutable access.
// #[cfg(feature = "zeroize")]
// impl<const N: usize> ExposeSecretMut
//     for crate::Fixed<crate::cloneable::array::CloneableArrayInner<N>>
// {
//     #[inline(always)]
//     fn expose_secret_mut(&mut self) -> &mut crate::cloneable::array::CloneableArrayInner<N> {
//         &mut self.inner
//     }
// }

// Implementation for [`Dynamic<CloneableVecInner>`] - provides mutable access.
// #[cfg(feature = "zeroize")]
// impl ExposeSecretMut for crate::Dynamic<crate::cloneable::vec::CloneableVecInner> {
//     #[inline(always)]
//     fn expose_secret_mut(&mut self) -> &mut crate::cloneable::vec::CloneableVecInner {
//         &mut self.inner
//     }
// }

// Implementation for [`Dynamic<CloneableStringInner>`] - provides mutable access.
// #[cfg(feature = "zeroize")]
// impl ExposeSecretMut for crate::Dynamic<crate::cloneable::string::CloneableStringInner> {
//     #[inline(always)]
//     fn expose_secret_mut(&mut self) -> &mut crate::cloneable::string::CloneableStringInner {
//         &mut self.inner
//     }
// }

// ============================================================================
// Specific Implementations for Test Types
// ============================================================================

/// Implementation for [`Fixed<u32>`] - provides mutable access.
impl ExposeSecretMut for Fixed<u32> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut u32 {
        &mut self.inner
    }
}
