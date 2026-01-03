// ==========================================================================
// src/dynamic.rs
// ==========================================================================

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
/// use secure_gate::Dynamic;
/// let secret: Dynamic<String> = "hunter2".into();
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// Mutable access:
/// ```
/// use secure_gate::Dynamic;
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
pub struct Dynamic<T: ?Sized>(Box<T>);

impl<T: ?Sized> Dynamic<T> {
    /// Wrap an already-boxed value.
    ///
    /// Zero-cost — just wraps the `Box`.
    #[inline(always)]
    pub fn new_boxed(value: Box<T>) -> Self {
        Dynamic(value)
    }

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

    /// Expose the inner value for read-only access.
    ///
    /// This is the **only** way to read the secret — loud and auditable.
    #[inline(always)]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Expose the inner value for mutable access.
    ///
    /// This is the **only** way to mutate the secret — loud and auditable.
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Clone impl — opt-in only when T is CloneableSecret
#[cfg(feature = "zeroize")]
impl<T: crate::CloneableSecret> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

// === Additional conversions ===

impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

// === Ergonomic helpers for common heap types ===
impl Dynamic<String> {
    /// Returns the length of the string in bytes.
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the string is empty (zero bytes).
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> Dynamic<Vec<T>> {
    /// Returns the number of elements in the vector.
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the vector is empty (zero elements).
    ///
    /// This is safe public metadata — does not expose the secret.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// === Convenient From impls ===
impl<T> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Box::new(value))
    }
}

impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self(boxed)
    }
}

impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self(Box::new(s.to_string()))
    }
}

// Constant-time equality — only available with `ct-eq` feature
#[cfg(feature = "ct-eq")]
impl<T> Dynamic<T>
where
    T: ?Sized + AsRef<[u8]>,
{
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::eq::ConstantTimeEq;
        self.expose_secret()
            .as_ref()
            .ct_eq(other.expose_secret().as_ref())
    }
}

// Random generation — only available with `rand` feature
#[cfg(feature = "rand")]
impl Dynamic<Vec<u8>> {
    /// Generate fresh random bytes of the specified length using the OS RNG.
    ///
    /// This is a convenience method that generates random bytes directly
    /// without going through `DynamicRng`. Equivalent to:
    /// `DynamicRng::generate(len).into_inner()`
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::Dynamic;
    /// let random: Dynamic<Vec<u8>> = Dynamic::generate_random(64);
    /// assert_eq!(random.len(), 64);
    /// # }
    /// ```
    #[inline]
    pub fn generate_random(len: usize) -> Self {
        crate::random::DynamicRng::generate(len).into_inner()
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
        crate::random::DynamicRng::try_generate(len)
            .map(|rng: crate::random::DynamicRng| rng.into_inner())
    }
}

// Zeroize integration
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
