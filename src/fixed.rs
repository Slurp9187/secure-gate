// src/fixed.rs
use core::ops::{Deref, DerefMut};

use crate::{Expose, ExposeMut};

pub struct Fixed<T>(pub T); // ← pub field

impl<T> Fixed<T> {
    pub fn new(value: T) -> Self {
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

impl<T> core::fmt::Debug for Fixed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> Fixed<T> {
    pub fn view(&self) -> Expose<'_, T> {
        Expose(&self.0)
    }

    pub fn view_mut(&mut self) -> ExposeMut<'_, T> {
        ExposeMut(&mut self.0)
    }
}

impl<T> Fixed<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

// From impls for common sizes (no orphan rule issue)
macro_rules! impl_from_array {
    ($($N:literal),*) => {$(
        impl From<[u8; $N]> for Fixed<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self {
                Self::new(arr)
            }
        }
    )*}
}
impl_from_array!(12, 16, 24, 32, 64);
