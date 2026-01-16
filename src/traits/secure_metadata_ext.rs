use super::SecureMetadata;

/// Extension trait for ergonomic metadata access on concrete types.
///
/// Import this to add `.len()` and `.is_empty()` methods to secret wrappers.
/// These delegate to the core [`SecureMetadata`] trait methods.
///
/// # Examples
///
/// ```
/// use secure_gate::{Fixed, SecureMetadataExt};
///
/// let secret = Fixed::new([1u8, 2, 3]);
/// assert_eq!(secret.len(), 3);
/// assert!(!secret.is_empty());
/// ```
pub trait SecureMetadataExt: SecureMetadata {
    /// Returns the length of the secret (delegates to [`SecureMetadata::len`]).
    #[inline(always)]
    fn len(&self) -> usize {
        <Self as SecureMetadata>::len(self)
    }

    /// Returns `true` if the secret is empty (delegates to [`SecureMetadata::is_empty`]).
    #[inline(always)]
    fn is_empty(&self) -> bool {
        <Self as SecureMetadata>::is_empty(self)
    }
}

// Blanket impl for all types satisfying SecureMetadata
impl<T: SecureMetadata + ?Sized> SecureMetadataExt for T {}
