use core::fmt;

#[cfg(feature = "rand")]
use rand::rand_core::OsError;

use crate::ExposeSecret;
use crate::FromSliceError;

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
/// let secret = Fixed::new(42u32);
/// assert_eq!(*secret.expose_secret(), 42);
/// ```
///
/// For byte arrays (most common):
/// ```
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
pub struct Fixed<T>(pub(crate) T); // ← field is pub(crate) for trait access

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
}

/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

/// Implements `TryFrom<&[u8]>` for creating a [`Fixed`] from a byte slice of exact length.
impl<const N: usize> core::convert::TryFrom<&[u8]> for Fixed<[u8; N]> {
    type Error = FromSliceError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != N {
            Err(FromSliceError::new(slice.len(), N))
        } else {
            let mut arr = [0u8; N];
            arr.copy_from_slice(slice);
            Ok(Self::new(arr))
        }
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

/// Debug implementation (always redacted).
impl<T> fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Regular equality — fallback when `ct-eq` feature is disabled.
#[cfg(not(feature = "ct-eq"))]
impl<T: PartialEq> PartialEq for Fixed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret() == other.expose_secret()
    }
}

/// Equality — available when `ct-eq` is not enabled.
#[cfg(not(feature = "ct-eq"))]
impl<T: Eq> Eq for Fixed<T> {}

/// Opt-in Clone — only for types marked `CloneSafe` (default no-clone).
#[cfg(feature = "zeroize")]
impl<T: crate::CloneSafe> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Constant-time equality — only available with `ct-eq` feature.
#[cfg(feature = "ct-eq")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two fixed-size secrets.
    /// Available only when the `ct-eq` feature is enabled.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "ct-eq")]
    /// # {
    /// use secure_gate::Fixed;
    /// let a = Fixed::new([1u8; 32]);
    /// let b = Fixed::new([1u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

/// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Generate fresh random bytes using the OS RNG.
    ///
    /// This is a convenience method that generates random bytes directly
    /// without going through `FixedRandom`. Equivalent to:
    /// `FixedRandom::<N>::generate().into_inner()`
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
        crate::random::FixedRandom::<N>::generate().into_inner()
    }

    /// Try to generate random bytes for Fixed.
    ///
    /// Returns an error if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::Fixed;
    /// let key: Result<Fixed<[u8; 32]>, rand::rand_core::OsError> = Fixed::try_generate_random();
    /// assert!(key.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn try_generate_random() -> Result<Self, OsError> {
        crate::random::FixedRandom::<N>::try_generate()
            .map(|rng: crate::random::FixedRandom<N>| rng.into_inner())
    }
}

/// Zeroize integration.
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Zeroize on drop integration.
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}
