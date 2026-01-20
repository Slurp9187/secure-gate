//! # Secret Exposure Traits
//!
//! This module defines traits for polymorphic secret access with controlled mutability and metadata.
//! These traits enable writing generic code that works across different secret wrapper types
//! while enforcing security guarantees.
//!
//! ## Key Traits
//!
//! - [`ExposeSecret`]: Read-only access to secret values including metadata
//!
//! ## Security Model
//!
//! - **Full access**: Core wrappers ([`Fixed`], [`Dynamic`]) implement [`ExposeSecret`], with mutable variants implementing [`ExposeSecretMut`]
//! - **Read-only**: Random ([`FixedRandom`], [`DynamicRandom`]) and encoding wrappers
//!   only implement [`ExposeSecret`] to prevent mutation
//! - **Zero-cost**: All implementations use `#[inline(always)]`
//!
/// ## Usage
///
/// Import these traits to access secret values and their metadata ergonomically.
use crate::{Dynamic, Fixed};

/// Trait for read-only access to secrets, including metadata.
///
/// Import this to enable `.expose_secret()`, `.len()`, and `.is_empty()`.
/// For mutable access, see [`super::ExposeSecretMut`].
pub trait ExposeSecret {
    /// The inner secret type being exposed.
    ///
    /// This can be a sized type (like `[u8; N]`) or unsized (like `str` or `[u8]`).
    type Inner: ?Sized;

    /// Expose the secret for read-only access.
    fn expose_secret(&self) -> &Self::Inner;

    /// Returns the length of the secret.
    fn len(&self) -> usize;

    /// Returns true if the secret is empty.
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Core Wrapper Implementations
// ============================================================================

/// Implementation for [`Fixed<[T; N]>`] - provides full read/write access for arrays.
///
/// [`Fixed`] is a core wrapper that allows both reading and mutation of secrets.
/// This implementation directly accesses the inner field.
impl<const N: usize, T> ExposeSecret for Fixed<[T; N]> {
    type Inner = [T; N];

    #[inline(always)]
    fn expose_secret(&self) -> &[T; N] {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        N
    }
}

/// Implementation for [`Dynamic<String>`] - provides full read/write access.
///
/// [`Dynamic<String>`] is a core wrapper that allows both reading and mutation of secrets.
/// This implementation directly accesses the inner field.
impl ExposeSecret for Dynamic<String> {
    type Inner = String;

    #[inline(always)]
    fn expose_secret(&self) -> &String {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Implementation for [`Dynamic<Vec<T>>`] - provides full read/write access.
///
/// [`Dynamic<Vec<T>>`] is a core wrapper that allows both reading and mutation of secrets.
/// This implementation directly accesses the inner field.
impl<T> ExposeSecret for Dynamic<Vec<T>> {
    type Inner = Vec<T>;

    #[inline(always)]
    fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Implementation for [`Fixed<CloneableArrayInner<N>>`] - exposes the inner wrapper.
// #[cfg(feature = "zeroize")]
// impl<const N: usize> ExposeSecret
//     for crate::Fixed<crate::cloneable::array::CloneableArrayInner<N>>
// {
//     type Inner = crate::cloneable::array::CloneableArrayInner<N>;

//     #[inline(always)]
//     fn expose_secret(&self) -> &crate::cloneable::array::CloneableArrayInner<N> {
//         &self.inner
//     }

//     #[inline(always)]
//     fn len(&self) -> usize {
//         N
//     }
// }

// ============================================================================
// Random Wrapper Implementations (Read-Only Only)
// ============================================================================

/// Implementation for [`Dynamic<CloneableStringInner>`] - exposes the inner wrapper.
// #[cfg(feature = "zeroize")]
// #[cfg(feature = "zeroize")]
// impl ExposeSecret for crate::Dynamic<crate::cloneable::string::CloneableStringInner> {
//     type Inner = crate::cloneable::string::CloneableStringInner;

//     #[inline(always)]
//     fn expose_secret(&self) -> &crate::cloneable::string::CloneableStringInner {
//         &self.inner
//     }

//     #[inline(always)]
//     fn len(&self) -> usize {
//         self.inner.0.len()
//     }
// }

/// Implementation for [`Dynamic<CloneableVecInner>`] - exposes the inner wrapper.
// #[cfg(feature = "zeroize")]
// #[cfg(feature = "zeroize")]
// impl ExposeSecret for crate::Dynamic<crate::cloneable::vec::CloneableVecInner> {
//     type Inner = crate::cloneable::vec::CloneableVecInner;

//     #[inline(always)]
//     fn expose_secret(&self) -> &crate::cloneable::vec::CloneableVecInner {
//         &self.inner
//     }

//     #[inline(always)]
//     fn len(&self) -> usize {
//         self.inner.0.len()
//     }
// }

/// Implementation for [`FixedRandom<N>`] - read-only access.
///
// Random wrappers purged in issue 68.

// Encoding wrappers purged in issue 65.

// ============================================================================
// Specific Implementations for Test Types
// ============================================================================

/// Implementation for [`Fixed<u32>`] - provides access for test compatibility.
impl ExposeSecret for Fixed<u32> {
    type Inner = u32;

    #[inline(always)]
    fn expose_secret(&self) -> &u32 {
        &self.inner
    }

    #[inline(always)]
    fn len(&self) -> usize {
        1
    }
}
