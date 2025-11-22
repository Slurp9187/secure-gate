// src/dynamic.rs
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

use crate::{Expose, ExposeMut};

pub struct Dynamic<T: ?Sized>(pub Box<T>); // ← pub field

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
}

impl<T: ?Sized> Deref for Dynamic<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for Dynamic<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> core::fmt::Debug for Dynamic<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: ?Sized> Dynamic<T> {
    pub fn view(&self) -> Expose<'_, T> {
        Expose(&self.0)
    }

    pub fn view_mut(&mut self) -> ExposeMut<'_, T> {
        ExposeMut(&mut self.0)
    }
}

impl<T: ?Sized> Dynamic<T> {
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

// Clone — conditional on feature to avoid double-boxing
#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for Dynamic<T>
where
    T: ?Sized,
{
    fn clone(&self) -> Self {
        Dynamic(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + zeroize::Zeroize> Clone for Dynamic<T> {
    fn clone(&self) -> Self {
        // Direct clone of SecretBox<T> — no new_boxed
        Dynamic(self.0.clone())
    }
}

// finish_mut
impl Dynamic<String> {
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut **self;
        s.shrink_to_fit();
        s
    }
}
impl Dynamic<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut **self;
        v.shrink_to_fit();
        v
    }
}
