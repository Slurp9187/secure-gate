/// Stack-allocated secure secret wrapper.
///
/// This is a zero-cost wrapper for fixed-size secrets like byte arrays or primitives.
/// The inner field is private, forcing all access through explicit methods.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access or borrowing.
/// - No implicit `Copy` — even for `[u8; N]`, duplication must be explicit via `.clone()`.
/// - `Debug` is always redacted.
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Fixed, ExposeSecret};
/// let secret = Fixed::new([42u8; 1]);
/// assert_eq!(secret.expose_secret()[0], 42);
/// ```
///
/// For byte arrays (most common):
/// ```
/// use secure_gate::{fixed_alias, Fixed, ExposeSecret};
/// fixed_alias!(Aes256Key, 32);
/// let key_bytes = [0x42u8; 32];
/// let key: Aes256Key = Fixed::from(key_bytes);
/// assert_eq!(key.len(), 32);
/// assert_eq!(key.expose_secret()[0], 0x42);
/// ```
///
/// With `zeroize` feature (automatic wipe on drop):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Fixed;
/// let mut secret = Fixed::new([1u8, 2, 3]);
/// drop(secret); // memory wiped automatically
/// # }
/// ```
#[cfg(feature = "rand")]
use rand::TryRngCore;

pub struct Fixed<T> {
    pub(crate) inner: T,
}

impl<T> Fixed<T> {
    /// Wrap a value in a `Fixed` secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// Wrap a value in a Fixed secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// const SECRET: Fixed<u32> = Fixed::new(42);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

// From implementations for byte arrays
impl<const N: usize> From<&[u8]> for Fixed<[u8; N]> {
    /// Create a `Fixed` from a byte slice, panicking on length mismatch.
    ///
    /// This is a fail-fast conversion for crypto contexts where exact length is expected.
    /// Panics if the slice length does not match the array size `N`.
    ///
    /// # Panics
    ///
    /// Panics if `slice.len() != N`.
    fn from(slice: &[u8]) -> Self {
        assert_eq!(
            slice.len(),
            N,
            "slice length mismatch: expected {}, got {}",
            N,
            slice.len()
        );
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Self::new(arr)
    }
}

// Macro-generated From constructor implementations
crate::impl_from_fixed!(array);
crate::impl_from_random_fixed!();

// Macro-generated equality implementations
crate::impl_ct_eq_fixed!();
crate::impl_hash_eq_fixed!();

// Macro-generated redacted debug implementations
crate::impl_redacted_debug!(Fixed<T>);

// Macro-generated serde implementations
crate::impl_serde_deserialize_fixed!(Fixed<T>);

// Macro-generated zeroize implementations
crate::impl_zeroize_integration_fixed!(Fixed<T>);
