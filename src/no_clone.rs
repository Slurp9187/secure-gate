// ==========================================================================
// src/no_clone.rs
// ==========================================================================

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

/// Non-cloneable stack-allocated secret wrapper.
///
/// This is a zero-cost newtype over `Fixed<T>` that deliberately omits `Clone` and `Copy`.
/// Use this when you want to enforce single-ownership and prevent accidental duplication of secrets.
///
/// Converts from `Fixed<T>` via `.no_clone()`.
///
/// # Examples
///
/// ```
/// use secure_gate::{Fixed, FixedNoClone};
/// let secret = Fixed::new([1u8; 32]);
/// let no_clone: FixedNoClone<[u8; 32]> = secret.no_clone();
/// // no_clone cannot be cloned
/// assert_eq!(no_clone.expose_secret()[0], 1);
/// ```
///
/// With `zeroize`:
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::FixedNoClone;
/// let mut secret = FixedNoClone::new([1u8, 2, 3]);
/// drop(secret); // wiped on drop
/// # }
/// ```
pub struct FixedNoClone<T>(T);

/// Non-cloneable heap-allocated secret wrapper.
///
/// This is a thin newtype over `Dynamic<T>` that deliberately omits `Clone`.
/// Use this for dynamic secrets where duplication must be prevented.
///
/// Converts from `Dynamic<T>` via `.no_clone()`.
///
/// # Examples
///
/// ```
/// use secure_gate::{Dynamic, DynamicNoClone};
/// let secret = Dynamic::new("hunter2".to_string());
/// let no_clone: DynamicNoClone<String> = secret.no_clone();
/// // no_clone cannot be cloned
/// assert_eq!(no_clone.expose_secret(), "hunter2");
/// ```
pub struct DynamicNoClone<T: ?Sized>(Box<T>);

impl<T> FixedNoClone<T> {
    /// Wrap a value in a non-cloneable fixed secret.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::FixedNoClone;
    /// let secret = FixedNoClone::new(42u32);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        FixedNoClone(value)
    }

    /// Expose the inner value for read-only access.
    ///
    /// This is the **only** way to read the secret — loud and auditable.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::FixedNoClone;
    /// let secret = FixedNoClone::new([42u8; 32]);
    /// assert_eq!(secret.expose_secret()[0], 42);
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
    /// use secure_gate::FixedNoClone;
    /// let mut secret = FixedNoClone::new([1u8, 2, 3]);
    /// secret.expose_secret_mut()[0] = 99;
    /// assert_eq!(secret.expose_secret()[0], 99);
    /// ```
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// Explicit zeroization — only available with `zeroize` feature
#[cfg(feature = "zeroize")]
impl<T: Zeroize> FixedNoClone<T> {
    /// Explicitly zeroize the secret immediately.
    ///
    /// This is useful when you want to wipe memory before the value goes out of scope,
    /// or when you want to make the zeroization intent explicit in the code.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "zeroize")]
    /// # {
    /// use secure_gate::FixedNoClone;
    /// let mut key = FixedNoClone::new([42u8; 32]);
    /// // ... use key ...
    /// key.zeroize_now();  // Explicit wipe - makes intent clear
    /// # }
    /// ```
    #[inline]
    pub fn zeroize_now(&mut self) {
        self.0.zeroize();
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    /// Wrap a boxed value in a non-cloneable dynamic secret.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::DynamicNoClone;
    /// let boxed = Box::new("secret".to_string());
    /// let no_clone = DynamicNoClone::new(boxed);
    /// ```
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        DynamicNoClone(value)
    }

    /// Expose the inner value for read-only access.
    ///
    /// This is the **only** way to read the secret — loud and auditable.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::DynamicNoClone;
    /// let secret = DynamicNoClone::new(Box::new("hunter2".to_string()));
    /// assert_eq!(secret.expose_secret(), "hunter2");
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
    /// use secure_gate::DynamicNoClone;
    /// let mut secret = DynamicNoClone::new(Box::new("hello".to_string()));
    /// secret.expose_secret_mut().push_str(" world");
    /// assert_eq!(secret.expose_secret(), "hello world");
    /// ```
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

// Explicit zeroization — only available with `zeroize` feature
#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> DynamicNoClone<T> {
    /// Explicitly zeroize the secret immediately.
    ///
    /// This is useful when you want to wipe memory before the value goes out of scope,
    /// or when you want to make the zeroization intent explicit in the code.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "zeroize")]
    /// # {
    /// use secure_gate::DynamicNoClone;
    /// let mut password = DynamicNoClone::new(Box::new("secret".to_string()));
    /// // ... use password ...
    /// password.zeroize_now();  // Explicit wipe - makes intent clear
    /// # }
    /// ```
    #[inline]
    pub fn zeroize_now(&mut self) {
        self.0.zeroize();
    }
}

impl<T> fmt::Debug for FixedNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: ?Sized> fmt::Debug for DynamicNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// === Ergonomic helpers for common heap types ===

impl DynamicNoClone<String> {
    /// Returns the length of the secret string in bytes (UTF-8).
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret string is empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> DynamicNoClone<Vec<T>> {
    /// Returns the length of the secret vector in elements.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret vector is empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
impl<T: Zeroize> Zeroize for FixedNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> Zeroize for DynamicNoClone<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for FixedNoClone<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicNoClone<T> {}
