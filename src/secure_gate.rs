// src/secure_gate.rs
//
// Unified secure wrapper – the new public name for 0.4.0+
// Routes to secrecy::SecretBox<T> when zeroize is on, Box<T> when off.
// Fixed-size types use fixed_stack.rs via aliases.

#![cfg_attr(not(feature = "unsafe-wipe"), forbid(unsafe_code))]

use alloc::boxed::Box;
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

#[cfg(not(feature = "zeroize"))]
use crate::{ExposeSecret, ExposeSecretMut};

/// Unified secure wrapper: `SecretBox<T>` (zeroize) or `Box<T>` (fallback).
/// This is the new public name starting with secure-gate 0.4.0.
#[cfg(feature = "zeroize")]
pub struct SecureGate<T: Zeroize + ?Sized>(SecretBox<T>);

#[cfg(not(feature = "zeroize"))]
pub struct SecureGate<T: ?Sized>(Box<T>);

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> SecureGate<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(SecretBox::new(Box::new(value)))
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> SecureGate<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> SecureGate<T> {
    #[inline]
    pub fn new_unsized(value: Box<T>) -> Self {
        Self(SecretBox::new(value))
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> SecureGate<T> {
    #[inline]
    pub fn new_unsized(value: Box<T>) -> Self {
        Self(value)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> SecureGate<T> {
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
impl<T: ?Sized> SecureGate<T> {
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
impl<T: Zeroize + ?Sized> Debug for SecureGate<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for SecureGate<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecret<T> for SecureGate<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> ExposeSecretMut<T> for SecureGate<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for SecureGate<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.expose().clone())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for SecureGate<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for SecureGate<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Default for SecureGate<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SecureGate<Vec<u8>> {
    fn zeroize(&mut self) {
        self.expose_mut().as_mut_slice().zeroize();
    }
}

#[cfg(all(feature = "zeroize", not(feature = "unsafe-wipe")))]
impl Zeroize for SecureGate<String> {
    fn zeroize(&mut self) {
        let len = self.expose().len();
        let zeros = "\0".repeat(len);
        self.expose_mut().replace_range(..len, &zeros);
    }
}

#[cfg(feature = "unsafe-wipe")]
impl Zeroize for SecureGate<String> {
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
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for SecureGate<T> {}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> SecureGate<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self(SecretBox::init_with(ctr))
    }
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(Self)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: Sized> SecureGate<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self::new(ctr())
    }
    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        ctr().map(Self::new)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> SecureGate<T> {
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self(SecretBox::init_with_mut(ctr))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> SecureGate<T> {
    pub fn into_inner(mut self) -> Box<T> {
        let value = self.0.expose_secret().clone();
        self.0.zeroize();
        Box::new(value)
    }
}
#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> SecureGate<T> {
    pub fn into_inner(self) -> Box<T> {
        self.0
    }
}

// Serde impls — unchanged, just renamed type
#[cfg(all(feature = "serde", feature = "zeroize"))]
impl<'de, T> de::Deserialize<'de> for SecureGate<T>
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
impl<'de, T> de::Deserialize<'de> for SecureGate<T>
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
impl<T> Serialize for SecureGate<T>
where
    T: SerializableSecret + Serialize + Zeroize + Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.expose().serialize(serializer)
    }
}
#[cfg(all(feature = "serde", not(feature = "zeroize")))]
impl<T> Serialize for SecureGate<T>
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

impl SecureGate<String> {
    #[inline]
    pub fn finish_mut(&mut self) -> &mut String {
        self.expose_mut().shrink_to_fit();
        self.expose_mut()
    }
}

impl SecureGate<Vec<u8>> {
    #[inline]
    pub fn finish_mut(&mut self) -> &mut Vec<u8> {
        self.expose_mut().shrink_to_fit();
        self.expose_mut()
    }
}
