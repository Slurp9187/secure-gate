// ==========================================================================
// src/no_clone.rs
// ==========================================================================

extern crate alloc;
use alloc::boxed::Box;
use core::fmt;

pub struct FixedNoClone<T>(T);

pub struct DynamicNoClone<T: ?Sized>(Box<T>);

impl<T> FixedNoClone<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        FixedNoClone(value)
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        DynamicNoClone(value)
    }

    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[inline(always)]
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

impl<T> fmt::Debug for FixedNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

impl<T: ?Sized> fmt::Debug for DynamicNoClone<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED_NO_CLONE]")
    }
}

// === Ergonomic helpers for common heap types ===

impl DynamicNoClone<String> {
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut *self.0;
        s.shrink_to_fit();
        s
    }

    /// Returns the length of the secret string in bytes (UTF-8).
    /// This is public metadata — does **not** expose the secret.
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
    pub fn finish_mut(&mut self) -> &mut Vec<T> {
        let v = &mut *self.0;
        v.shrink_to_fit();
        v
    }

    /// Returns the length of the secret vector in elements.
    /// This is public metadata — does **not** expose the secret.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret vector is empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns a shared slice of the secret bytes.
    /// Requires explicit intent — consistent with the crate's philosophy.
    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        self.expose_secret()
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
