// src/dynamic.rs
//! Heap-allocated secure wrappers for dynamic secrets.
//!
//! `Dynamic<T>` is a zero-cost wrapper around `Box<T>` that:
//! - Prevents accidental cloning/leaking via `Debug` redaction.
//! - Provides explicit access via `.expose_secret()` (canonical API).
//! - Supports idiomatic `.into()` conversions from owned values.
//! - Works seamlessly with [`dynamic_alias!`] for type aliases.
//!
//! # Examples
//!
//! ```
//! use secure_gate::{dynamic_alias, Dynamic};
//!
//! dynamic_alias!(Password, String);
//!
//! let pw: Password = "hunter2".into();
//! assert_eq!(pw.expose_secret(), "hunter2");
//! ```

extern crate alloc;

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

/// A zero-cost, heap-allocated wrapper for sensitive data.
///
/// `Dynamic<T>` stores its value on the heap via `Box<T>`. It behaves like `T`
/// thanks to `Deref`/`DerefMut`, but redacts itself in debug output and requires
/// explicit access to the inner value.
///
/// Use this for dynamic-sized secrets like passwords or variable-length keys.
///
/// # Examples
///
/// ```
/// use secure_gate::Dynamic;
///
/// let secret: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
/// assert_eq!(secret.expose_secret(), &[1, 2, 3]);
/// ```
pub struct Dynamic<T: ?Sized>(pub Box<T>);

impl<T: ?Sized> Dynamic<T> {
    /// Creates a new `Dynamic` from a boxed value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let secret = Dynamic::new_boxed(Box::new("hello".to_string()));
    /// assert_eq!(secret.expose_secret(), "hello");
    /// ```
    #[inline(always)]
    pub fn new_boxed(value: Box<T>) -> Self {
        Dynamic(value)
    }

    /// Creates a new `Dynamic` from a value that can be converted into `Box<T>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let secret: Dynamic<String> = Dynamic::new("hunter2".to_string());
    /// assert_eq!(secret.expose_secret(), "hunter2");
    /// ```
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        Dynamic(value.into())
    }
}

impl<T: ?Sized> Deref for Dynamic<T> {
    type Target = T;

    /// Dereferences the wrapper to access the inner value immutably.
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for Dynamic<T> {
    /// Dereferences the wrapper mutably to access the inner value.
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    /// Formats the value as "[REDACTED]" to prevent leakage in debug output.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: ?Sized> Dynamic<T> {
    /// Accesses the secret value immutably.
    ///
    /// This is the canonical, explicit way to read the secret.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let secret: Dynamic<String> = "secret".into();
    /// assert_eq!(secret.expose_secret(), "secret");
    /// ```
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Accesses the secret value mutably.
    ///
    /// Use for in-place modifications.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let mut secret: Dynamic<String> = "hello".into();
    /// secret.expose_secret_mut().push('!');
    /// assert_eq!(secret.expose_secret(), "hello!");
    /// ```
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// **Deprecated**: Use [`expose_secret`] instead.
    ///
    /// This method forwards to [`expose_secret`] for compatibility.
    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    /// **Deprecated**: Use [`expose_secret_mut`] instead.
    ///
    /// This method forwards to [`expose_secret_mut`] for compatibility.
    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    /// Consumes the wrapper and returns the inner boxed value.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let secret: Dynamic<String> = "owned".into();
    /// let owned: Box<String> = secret.into_inner();
    /// assert_eq!(&*owned, "owned");
    /// ```
    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

// Clone impls
#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for Dynamic<T> {
    /// Clones the wrapper, cloning the inner value.
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + zeroize::Zeroize> Clone for Dynamic<T> {
    /// Clones the wrapper, cloning the inner value.
    #[inline(always)]
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

impl Dynamic<String> {
    /// Shrinks the string's capacity to fit its length and returns a mutable reference.
    ///
    /// Use this to eliminate slack memory after mutations.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let mut secret: Dynamic<String> = String::with_capacity(100).into();
    /// secret.push_str("short");
    /// let s: &mut String = secret.finish_mut();
    /// assert_eq!(s.capacity(), 5);
    /// ```
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut **self;
        s.shrink_to_fit();
        s
    }
}

impl Dynamic<Vec<u8>> {
    /// Shrinks the vector's capacity to fit its length and returns a mutable reference.
    ///
    /// Use this to eliminate slack memory after mutations.
    ///
    /// # Examples
    ///
    /// ```
    /// use secure_gate::Dynamic;
    ///
    /// let mut secret: Dynamic<Vec<u8>> = Vec::with_capacity(100).into();
    /// secret.extend_from_slice(b"short");
    /// let v: &mut Vec<u8> = secret.finish_mut();
    /// assert_eq!(v.capacity(), 5);
    /// ```
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut **self;
        v.shrink_to_fit();
        v
    }
}

// ——— .into() ergonomics ———
/// Converts an owned value into a `Dynamic`.
///
/// # Examples
///
/// ```
/// use secure_gate::Dynamic;
///
/// let secret: Dynamic<Vec<u8>> = vec![1, 2, 3].into();
/// assert_eq!(secret.expose_secret(), &[1, 2, 3]);
/// ```
impl<T> From<T> for Dynamic<T>
where
    T: Sized,
{
    #[inline(always)]
    fn from(value: T) -> Self {
        Self(Box::new(value))
    }
}

/// Converts a `Box<T>` into a `Dynamic<T>`.
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self(boxed)
    }
}

/// Convenience conversion from `&str` to `Dynamic<String>`.
///
/// # Examples
///
/// ```
/// use secure_gate::Dynamic;
///
/// let secret: Dynamic<String> = "password".into();
/// assert_eq!(secret.expose_secret(), "password");
/// ```
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(s: &str) -> Self {
        Self(Box::new(s.to_string()))
    }
}
