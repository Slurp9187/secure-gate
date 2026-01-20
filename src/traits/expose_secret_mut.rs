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
