// ==========================================================================
// src/fixed.rs
// ==========================================================================

use core::convert::From;
use core::ops::{Deref, DerefMut};

pub struct Fixed<T>(pub T);

impl<T> Fixed<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed(value)
    }
}

impl<T> Deref for Fixed<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Fixed<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<const N: usize> Fixed<[u8; N]> {
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N, "slice length mismatch");
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes[..N]);
        Self::new(arr)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

impl<const N: usize> AsRef<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for Fixed<[u8; N]> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> Fixed<T> {
    #[inline(always)]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view(&self) -> &T {
        self.expose_secret()
    }

    #[deprecated(since = "0.5.5", note = "use `expose_secret_mut` instead")]
    #[doc(hidden)]
    #[inline(always)]
    pub fn view_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Fixed<T> {
    #[inline(always)]
    pub fn no_clone(self) -> crate::FixedNoClone<T> {
        crate::FixedNoClone::new(self.0)
    }
}

impl<T: Clone> Clone for Fixed<T> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const N: usize> Copy for Fixed<[u8; N]> where [u8; N]: Copy {}
