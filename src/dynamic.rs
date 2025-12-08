// ==========================================================================
// src/dynamic.rs
// ==========================================================================

extern crate alloc;

use alloc::boxed::Box;

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


    /// Convert to a non-cloneable variant.
    ///
    /// Prevents accidental cloning of the secret.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::{Dynamic, DynamicNoClone};
    /// let secret = Dynamic::<String>::new("no copy".to_string());
    /// let no_clone: DynamicNoClone<String> = secret.no_clone();
    /// assert_eq!(no_clone.expose_secret(), "no copy");
    /// ```
    #[inline(always)]
    pub fn no_clone(self) -> crate::DynamicNoClone<T> {
        crate::DynamicNoClone::new(self.0)
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// Clone impls — gated correctly
#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + zeroize::Zeroize> Clone for Dynamic<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

// === Ergonomic helpers for common heap types ===
impl Dynamic<String> {
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> Dynamic<Vec<T>> {
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

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

// Constant-time equality — only available with `conversions` feature
#[cfg(feature = "conversions")]
impl<T> Dynamic<T>
where
    T: ?Sized + AsRef<[u8]>,
{
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::conversions::SecureConversionsExt;
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
        crate::rng::DynamicRng::generate(len).into_inner()
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
