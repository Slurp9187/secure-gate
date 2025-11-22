// src/fixed.rs
use core::ops::{Deref, DerefMut};

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
        f.write_str("Fixed<[REDACTED]>")
    }
}
