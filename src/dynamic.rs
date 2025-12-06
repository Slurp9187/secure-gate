// ==========================================================================
// src/dynamic.rs
// ==========================================================================

extern crate alloc;

use alloc::boxed::Box;

/// Heap-allocated secure secret wrapper.
///
/// All access to the inner value requires an explicit `.expose_secret()` call.
/// No `Deref`, no `AsRef`, no `as_slice()` — every read/write is loud and grep-able.
pub struct Dynamic<T: ?Sized>(Box<T>);

impl<T: ?Sized> Dynamic<T> {
    #[inline(always)]
    pub fn new_boxed(value: Box<T>) -> Self {
        Dynamic(value)
    }

    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        Dynamic(value.into())
    }

    /// Expose the secret for read-only access.
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Expose the secret for mutable access.
    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner `Box<T>`.
    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }

    /// Convert into a non-cloneable variant.
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
impl<T: Clone + ?Sized> Clone for Dynamic<T> {
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
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut *self.0;
        s.shrink_to_fit();
        s
    }
}

impl Dynamic<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut *self.0;
        v.shrink_to_fit();
        v
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

// ========================================================================
// REMOVED: PartialEq / Eq
// ========================================================================
// Non-constant-time equality was a timing-attack footgun.
// Users must now use `.ct_eq()` when the `conversions` feature is enabled.

// Constant-time equality — only available with `conversions` feature
#[cfg(feature = "conversions")]
impl<T> Dynamic<T>
where
    T: ?Sized + AsRef<[u8]>,
{
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two `Dynamic` secrets.
    /// Available only when the `conversions` feature is enabled.
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::conversions::SecureConversionsExt;
        self.expose_secret()
            .as_ref()
            .ct_eq(other.expose_secret().as_ref())
    }
}

// ========================================================================
// Zeroize integration
// ========================================================================
#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::Zeroize for Dynamic<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + zeroize::Zeroize> zeroize::ZeroizeOnDrop for Dynamic<T> {}
