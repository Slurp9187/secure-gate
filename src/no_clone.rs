// ==========================================================================
// src/no_clone.rs
// ==========================================================================

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

extern crate alloc;
use alloc::boxed::Box;

#[doc(hidden)]
pub enum PhantomNonClone {}

pub struct FixedNoClone<T>(T, PhantomData<PhantomNonClone>);

pub struct DynamicNoClone<T: ?Sized>(Box<T>, PhantomData<PhantomNonClone>);

impl<T> FixedNoClone<T> {
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        FixedNoClone(value, PhantomData)
    }
}

impl<T: ?Sized> DynamicNoClone<T> {
    #[inline(always)]
    pub fn new(value: Box<T>) -> Self {
        DynamicNoClone(value, PhantomData)
    }
}

impl<T> Deref for FixedNoClone<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for FixedNoClone<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized> Deref for DynamicNoClone<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for DynamicNoClone<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
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

impl<T> FixedNoClone<T> {
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

impl DynamicNoClone<String> {
    pub fn finish_mut(&mut self) -> &mut String {
        let s = &mut **self;
        s.shrink_to_fit();
        s
    }
}

impl DynamicNoClone<Vec<u8>> {
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        let v = &mut **self;
        v.shrink_to_fit();
        v
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
        (**self).zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize> ZeroizeOnDrop for FixedNoClone<T> {}

#[cfg(feature = "zeroize")]
impl<T: ?Sized + Zeroize> ZeroizeOnDrop for DynamicNoClone<T> {}
