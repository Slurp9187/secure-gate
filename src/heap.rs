// src/heap.rs
//
// Heap-allocated secure wrapper with feature-gated zeroization

#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]

use alloc::boxed::Box;

#[cfg(feature = "zeroize")]
use alloc::{string::String, vec::Vec};

use core::fmt::{self, Debug};

#[cfg(all(feature = "serde", feature = "zeroize"))]
use secrecy::SerializableSecret;
#[cfg(feature = "zeroize")]
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
#[cfg(feature = "serde")]
use serde::{de, Serialize, Serializer};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
use core::any::Any;

#[cfg(not(feature = "zeroize"))]
use crate::{ExposeSecret, ExposeSecretMut};

#[cfg(feature = "zeroize")]
pub(crate) trait AsAnyMut {
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
#[cfg(feature = "zeroize")]
impl<T: 'static> AsAnyMut for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Heap-allocated secure wrapper: `SecretBox<T>` (zeroize) or `Box<T>` (fallback).
#[cfg(feature = "zeroize")]
pub struct HeapSecure<T: Zeroize + ?Sized>(SecretBox<T>);
#[cfg(not(feature = "zeroize"))]
pub struct HeapSecure<T: ?Sized>(Box<T>);

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> HeapSecure<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> HeapSecure<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> HeapSecure<T> {
    #[inline]
    pub fn expose(&self) -> &T {
        self.0.expose_secret()
    }
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> HeapSecure<T> {
    #[inline]
    pub fn expose(&self) -> &T {
        &self.0
    }
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Debug for HeapSecure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for HeapSecure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecret<T> for HeapSecure<T> {
    fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }
}
#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ExposeSecretMut<T> for HeapSecure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecret<T> for HeapSecure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecretMut<T> for HeapSecure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for HeapSecure<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.expose().clone())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Clone + ?Sized> Clone for HeapSecure<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for HeapSecure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Default for HeapSecure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for HeapSecure<Vec<u8>> {
    fn zeroize(&mut self) {
        self.expose_mut().as_mut_slice().zeroize();
    }
}

#[cfg(all(feature = "zeroize", not(feature = "unsafe-wipe")))]
impl Zeroize for HeapSecure<String> {
    fn zeroize(&mut self) {
        let len = self.expose().len();
        let zeros = "\0".repeat(len);
        self.expose_mut().replace_range(..len, &zeros);
    }
}

#[cfg(feature = "unsafe-wipe")]
impl Zeroize for HeapSecure<String> {
    fn zeroize(&mut self) {
        use core::hint::black_box;
        use core::sync;

        let original_len = self.expose().len();
        let original_cap = self.expose().capacity();
        black_box((original_len, original_cap));

        let s = self.expose_mut();
        let vec = unsafe { s.as_mut_vec() };

        unsafe {
            let ptr = vec.as_mut_ptr();
            let cap = vec.capacity();
            debug_assert!(cap >= vec.len(), "Cap < len: invariant broken");
            core::slice::from_raw_parts_mut(ptr, cap).zeroize();
            sync::atomic::compiler_fence(sync::atomic::Ordering::SeqCst);
            let _dummy = [0u8; 1024];
            black_box(&_dummy);
        }

        debug_assert_eq!(s.len(), original_len, "Len drifted");
        debug_assert_eq!(s.capacity(), original_cap, "Cap drifted");
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for HeapSecure<T> {}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> HeapSecure<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self(SecretBox::init_with(ctr))
    }
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(Self)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> HeapSecure<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self::new(ctr())
    }
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        ctr().map(Self::new)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> HeapSecure<T> {
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self(SecretBox::init_with_mut(ctr))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> HeapSecure<T> {
    pub fn into_inner(mut self) -> Box<T> {
        let value = self.0.expose_secret().clone();
        self.0.zeroize();
        Box::new(value)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> HeapSecure<T> {
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de, T> de::Deserialize<'de> for HeapSecure<T>
where
    T: de::Deserialize<'de> + Zeroize + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::new)
    }
}
#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<'de, T> de::Deserialize<'de> for HeapSecure<T>
where
    T: de::Deserialize<'de> + Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<T> Serialize for HeapSecure<T>
where
    T: SerializableSecret + Serialize + Sized + Zeroize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}
#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<T> Serialize for HeapSecure<T>
where
    T: Serialize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized + 'static> HeapSecure<T> {
    pub fn finish_mut(&mut self) -> &mut T {
        if let Some(v) = self.expose_mut().as_any_mut().downcast_mut::<Vec<u8>>() {
            v.shrink_to_fit();
        } else if let Some(s) = self.expose_mut().as_any_mut().downcast_mut::<String>() {
            s.shrink_to_fit();
        }
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> HeapSecure<T> {
    pub fn new_unsized(boxed: Box<T>) -> Self {
        Self(SecretBox::new(boxed))
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> HeapSecure<T> {
    pub fn new_unsized(boxed: Box<T>) -> Self {
        Self(boxed)
    }
}
