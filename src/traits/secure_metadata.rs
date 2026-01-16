/// # Secure Metadata Traits
///
/// This module provides traits for safely accessing metadata about secret values
/// without exposing the secrets themselves. This enables operations like length
/// checks, emptiness queries, and bounds checking without compromising security.
///
/// ## Key Traits
///
/// - [`SecureMetadata`]: Core trait providing length and emptiness queries
///
/// ## Security Model
///
/// - **No exposure**: Metadata methods never reveal secret contents
/// - **Safe queries**: All operations are constant-time and side-channel resistant
/// - **Universal support**: Implemented for all secret wrapper types
/// - **Zero-cost**: All implementations use `#[inline(always)]`
///
/// ## Usage
///
/// ```
/// use secure_gate::{Fixed, Dynamic, SecureMetadata};
///
/// // Check lengths without exposing secrets
/// let array_secret: Fixed<[u8; 32]> = Fixed::new([0u8; 32]);
/// assert_eq!(array_secret.len(), 32);
/// assert!(!array_secret.is_empty());
///
/// let string_secret: Dynamic<String> = Dynamic::new("secret".to_string());
/// assert_eq!(string_secret.len(), 6);
/// ```
use crate::{Dynamic, Fixed};

#[cfg(feature = "rand")]
use crate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "zeroize")]
use crate::cloneable::{CloneableArray, CloneableString, CloneableVec};

#[cfg(feature = "encoding-hex")]
use crate::encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
use crate::encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
use crate::encoding::bech32::Bech32String;

/// Safe access to secret metadata without exposing contents.
///
/// This trait provides methods to query properties of secret values (like length
/// and emptiness) without revealing the actual secret data. All implementations
/// are guaranteed to be constant-time and side-channel resistant.
///
/// ## Security
///
/// - Never exposes secret contents, only metadata
/// - All operations are auditable and safe
/// - Used for bounds checking, allocation, and validation
pub trait SecureMetadata {
    /// Returns the length of the secret in its natural units.
    ///
    /// For byte-based secrets, this returns the number of bytes.
    /// For string-based secrets, this returns the number of bytes in UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::{Fixed, SecureMetadata};
    /// let secret = Fixed::new([1u8, 2, 3]);
    /// assert_eq!(secret.len(), 3);
    /// ```
    fn len(&self) -> usize;

    /// Returns `true` if the secret has zero length.
    ///
    /// This is a convenience method that checks if `len() == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::{Fixed, SecureMetadata};
    /// let empty = Fixed::new([]);
    /// let non_empty = Fixed::new([42]);
    ///
    /// assert!(empty.is_empty());
    /// assert!(!non_empty.is_empty());
    /// ```
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// Core Wrapper Implementations
// ============================================================================

/// Implementation for [`Fixed<[u8; N]>`] - constant-time length and emptiness queries.
///
/// Fixed-size byte arrays have compile-time known lengths, making this
/// implementation zero-cost and infallible.
impl<const N: usize> SecureMetadata for Fixed<[u8; N]> {
    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

/// Implementation for [`Dynamic<String>`] - UTF-8 byte length.
///
/// Returns the byte length of the string content, not the character count.
/// This matches the behavior of `String::len()`.
impl SecureMetadata for Dynamic<String> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Implementation for [`Dynamic<Vec<T>>`] - element count.
///
/// Returns the number of elements in the vector, not bytes. For `Vec<u8>`,
/// this is equivalent to byte count.
impl<T> SecureMetadata for Dynamic<Vec<T>> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ============================================================================
// Random Wrapper Implementations
// ============================================================================

/// Implementation for [`FixedRandom<N>`] - random byte array length.
///
/// Random wrappers delegate to their underlying fixed-size arrays.
#[cfg(feature = "rand")]
impl<const N: usize> SecureMetadata for FixedRandom<N> {
    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

/// Implementation for [`DynamicRandom`] - random byte vector length.
///
/// Random wrappers delegate to their underlying dynamic vectors.
#[cfg(feature = "rand")]
impl SecureMetadata for DynamicRandom {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0 .0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }
}

// ============================================================================
// Encoding Wrapper Implementations
// ============================================================================

/// Implementation for [`HexString`] - encoded string length.
///
/// Returns the length of the hex-encoded string (e.g., "deadbeef" has length 8).
#[cfg(feature = "encoding-hex")]
impl SecureMetadata for HexString {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Implementation for [`Base64String`] - encoded string length.
///
/// Returns the length of the base64-encoded string.
#[cfg(feature = "encoding-base64")]
impl SecureMetadata for Base64String {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Implementation for [`Bech32String`] - encoded string length.
///
/// Returns the length of the bech32/bech32m-encoded string.
#[cfg(feature = "encoding-bech32")]
impl SecureMetadata for Bech32String {
    #[inline(always)]
    fn len(&self) -> usize {
        self.inner.0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.inner.0.is_empty()
    }
}

// ============================================================================
// Cloneable Wrapper Implementations
// ============================================================================

/// Implementation for [`CloneableArray<N>`] - constant-time length queries.
///
/// Cloneable fixed arrays have compile-time known lengths.
#[cfg(feature = "zeroize")]
impl<const N: usize> SecureMetadata for CloneableArray<N> {
    #[inline(always)]
    fn len(&self) -> usize {
        N
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        N == 0
    }
}

/// Implementation for [`CloneableString`] - UTF-8 byte length.
///
/// Delegates to the inner string's length method.
#[cfg(feature = "zeroize")]
impl SecureMetadata for CloneableString {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0 .0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }
}

/// Implementation for [`CloneableVec`] - element count.
///
/// Returns the number of elements in the cloneable vector.
#[cfg(feature = "zeroize")]
impl SecureMetadata for CloneableVec {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0 .0.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }
}
