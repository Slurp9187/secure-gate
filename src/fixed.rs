// ==========================================================================
// src/fixed.rs
// ==========================================================================

use core::fmt;

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
/// use secure_gate::Fixed;
/// let secret = Fixed::new(42u32);
/// assert_eq!(*secret.expose_secret(), 42);
/// ```
///
/// For byte arrays (most common):
/// ```
/// use secure_gate::{Fixed, fixed_alias};
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
pub struct Fixed<T>(T); // ← field is PRIVATE

impl<T> Fixed<T> {
    /// Wrap a value in a `Fixed` secret.
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
        Fixed(value)
    }

    /// Expose the inner value for read-only access.
    ///
    /// This is the **only** way to read the secret — loud and auditable.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let secret = Fixed::new("hunter2");
    /// assert_eq!(secret.expose_secret(), &"hunter2");
    /// ```
    #[inline(always)]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Expose the inner value for mutable access.
    ///
    /// This is the **only** way to mutate the secret — loud and auditable.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let mut secret = Fixed::new([1u8, 2, 3]);
    /// secret.expose_secret_mut()[0] = 42;
    /// assert_eq!(secret.expose_secret()[0], 42);
    /// ```
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// Useful for passing secrets to functions that consume ownership.
    ///
    /// Note: If `zeroize` is enabled, prefer dropping the `Fixed` to ensure wiping.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let secret = Fixed::new(42u32);
    /// let inner = secret.into_inner();
    /// assert_eq!(inner, 42);
    /// ```
    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Convert to a non-cloneable variant.
    ///
    /// This prevents accidental cloning of the secret.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let secret = Fixed::new([1u8; 32]);
    /// let no_clone = secret.no_clone();
    /// // no_clone cannot be cloned
    /// ```
    #[inline(always)]
    pub fn no_clone(self) -> crate::FixedNoClone<T> {
        crate::FixedNoClone::new(self.0)
    }
}

// === Byte-array specific helpers ===

impl<const N: usize> Fixed<[u8; N]> {
    /// Returns the fixed length in bytes.
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if the fixed secret is empty (zero-length).
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Create from a byte slice of exactly `N` bytes.
    ///
    /// Panics if the slice length does not match `N`.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let bytes: &[u8] = &[1, 2, 3];
    /// let secret = Fixed::<[u8; 3]>::from_slice(bytes);
    /// assert_eq!(secret.expose_secret(), &[1, 2, 3]);
    /// ```
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    /// Wrap a raw byte array in a `Fixed` secret.
    ///
    /// Zero-cost conversion.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let key: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
    /// ```
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

// Debug is always redacted
impl<T> fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Explicit Clone only — no implicit Copy
impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// REMOVED: Copy impl for Fixed<[u8; N]>
// Implicit copying of secrets is a footgun — duplication must be intentional.

// Constant-time equality — only available with `conversions` feature
#[cfg(feature = "conversions")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two fixed-size secrets.
    /// Available only when the `conversions` feature is enabled.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "conversions")]
    /// # {
    /// use secure_gate::Fixed;
    /// let a = Fixed::new([1u8; 32]);
    /// let b = Fixed::new([1u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::conversions::SecureConversionsExt;
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

// Random generation — only available with `rand` feature
#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Generate fresh random bytes using the OS RNG.
    ///
    /// This is a convenience method that generates random bytes directly
    /// without going through `FixedRng`. Equivalent to:
    /// `FixedRng::<N>::generate().into_inner()`
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::Fixed;
    /// let key: Fixed<[u8; 32]> = Fixed::generate_random();
    /// # }
    /// ```
    #[inline]
    pub fn generate_random() -> Self {
        crate::rng::FixedRng::<N>::generate().into_inner()
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
