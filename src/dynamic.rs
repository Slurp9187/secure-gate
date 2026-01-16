extern crate alloc;

use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::rand_core::OsError;

/// Heap-allocated secure secret wrapper.
///
/// This is a thin wrapper around `Box<T>` with enforced explicit exposure.
/// Suitable for dynamic-sized secrets like `String` or `Vec<u8>`.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access.
/// - `Debug` is always redacted.
/// - With `zeroize`, wipes the entire allocation on drop (including spare capacity).
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let secret: Dynamic<String> = "hunter2".into();
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// With already-boxed values:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let boxed_secret = Box::new("hunter2".to_string());
/// let secret: Dynamic<String> = boxed_secret.into(); // or Dynamic::from(boxed_secret)
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// Mutable access:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
/// let mut secret = Dynamic::<String>::new("pass".to_string());
/// secret.expose_secret_mut().push('!');
/// assert_eq!(secret.expose_secret(), "pass!");
/// ```
///
/// With `zeroize` (automatic wipe):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Dynamic;
/// let secret = Dynamic::<Vec<u8>>::new(vec![1u8; 32]);
/// drop(secret); // heap wiped automatically
/// # }
/// ```
pub struct Dynamic<T: ?Sized>(pub(crate) Box<T>);

impl<T: ?Sized> Dynamic<T> {
    /// Wrap a value by boxing it.
    ///
    /// Uses `Into<Box<T>>` for flexibility.
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        Dynamic(value.into())
    }
}

/// Debug implementation (always redacted).
impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Opt-in Clone — only for types marked `CloneSafe`.
#[cfg(feature = "zeroize")]
impl<T: crate::CloneSafe> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

/// # Additional conversions
/// Wrap a byte slice into a [`Dynamic`] [`Vec<u8>`].
impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

/// # Ergonomic helpers for common heap types
impl Dynamic<String> {}

impl<T> Dynamic<Vec<T>> {}

/// # Convenient From impls
/// Wrap a value in a [`Dynamic`] secret by boxing it.
impl<T> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Box::new(value))
    }
}

/// Wrap a boxed value in a [`Dynamic`] secret.
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self(boxed)
    }
}

/// Wrap a string slice in a [`Dynamic`] [`String`].
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self(Box::new(s.to_string()))
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<String> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two `Dynamic<String>` instances in constant time
    /// to prevent timing attacks. The strings are compared as UTF-8 byte sequences.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ct-eq")]
    /// # {
    /// use secure_gate::Dynamic;
    /// let a: Dynamic<String> = Dynamic::new("secret".to_string());
    /// let b: Dynamic<String> = Dynamic::new("secret".to_string());
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

#[cfg(feature = "ct-eq")]
impl Dynamic<Vec<u8>> {
    /// Constant-time equality comparison.
    ///
    /// Compares the byte contents of two `Dynamic<Vec<u8>>` instances in constant time
    /// to prevent timing attacks. The vectors are compared as byte slices.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "ct-eq")]
    /// # {
    /// use secure_gate::Dynamic;
    /// let a: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
    /// let b: Dynamic<Vec<u8>> = Dynamic::new(vec![1, 2, 3]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::ct_eq::ConstantTimeEq;
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

/// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<Vec<u8>> {
    /// Generate fresh random bytes of the specified length using the OS RNG.
    ///
    /// This is a convenience method that generates random bytes directly
    /// without going through `DynamicRandom`. Equivalent to:
    /// `DynamicRandom::generate(len).into_inner()`
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, ExposeSecret};
    /// let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
    /// assert_eq!(random.len(), 64);
    /// # }
    /// ```
    #[inline]
    pub fn generate_random(len: usize) -> Self {
        crate::random::DynamicRandom::generate(len).into_inner()
    }

    /// Try to generate random bytes for Dynamic.
    ///
    /// Returns an error if the RNG fails.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::Dynamic;
    /// let random: Result<Dynamic<Vec<u8>>, rand::rand_core::OsError> = Dynamic::try_generate_random(64);
    /// assert!(random.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn try_generate_random(len: usize) -> Result<Self, OsError> {
        crate::random::DynamicRandom::try_generate(len)
            .map(|rng: crate::random::DynamicRandom| rng.into_inner())
    }
}

/// Zeroize integration.
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Zeroize on drop integration.
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
