// src/secure_gate.rs
//
// Unified secure wrapper – the new public name for 0.4.0+
// Routes to secrecy::SecretBox<T> when zeroize is on, Box<T> when off.
// Adds configurable zeroization modes for Vec<u8>/String (Issue #24)

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

// ──────────────────────────────────────────────────────────────
// Zeroization mode selection – new in 0.4.1 (Issue #24)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ZeroizeMode {
    Safe,
    #[cfg(feature = "unsafe-wipe")]
    Full,
    Passthrough,
}

#[cfg(feature = "zeroize")]
trait Wipable {
    fn safe_wipe(&mut self);
    #[cfg(feature = "unsafe-wipe")]
    unsafe fn unsafe_full_wipe(&mut self);
}

#[cfg(feature = "zeroize")]
impl Wipable for Vec<u8> {
    fn safe_wipe(&mut self) {
        self.as_mut_slice().zeroize();
    }

    #[cfg(feature = "unsafe-wipe")]
    unsafe fn unsafe_full_wipe(&mut self) {
        use core::{hint::black_box, sync::atomic};

        let ptr = self.as_mut_ptr();
        let cap = self.capacity();

        // Empty Vec can have non-null ptr with cap > 0, or null ptr with cap == 0.
        // We must wipe whenever cap > 0 regardless of whether ptr is null.
        if cap > 0 && !ptr.is_null() {
            core::slice::from_raw_parts_mut(ptr, cap).zeroize();
            atomic::compiler_fence(atomic::Ordering::SeqCst);
            black_box([0u8; 1024]);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Wipable for String {
    fn safe_wipe(&mut self) {
        let len = self.len();
        self.clear();
        for _ in 0..len {
            self.push('\0');
        }
    }

    #[cfg(feature = "unsafe-wipe")]
    unsafe fn unsafe_full_wipe(&mut self) {
        self.as_mut_vec().unsafe_full_wipe();
    }
}

// ──────────────────────────────────────────────────────────────
// SecureGate – zeroize path
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
pub struct SecureGate<T: Zeroize + ?Sized> {
    inner: SecretBox<T>,
    mode: ZeroizeMode,
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> SecureGate<T> {
    #[inline(always)]
    pub fn new(value: T) -> Self {
        Self::with_mode(value, ZeroizeMode::Safe)
    }

    pub fn with_mode(value: T, mode: ZeroizeMode) -> Self {
        Self {
            inner: SecretBox::new(Box::new(value)),
            mode,
        }
    }

    #[cfg(feature = "unsafe-wipe")]
    #[inline]
    pub fn new_full_wipe(value: T) -> Self {
        Self::with_mode(value, ZeroizeMode::Full)
    }

    #[inline]
    pub fn new_passthrough(value: T) -> Self {
        Self::with_mode(value, ZeroizeMode::Passthrough)
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> SecureGate<T> {
    #[inline(always)]
    pub fn new_unsized(value: Box<T>) -> Self {
        Self {
            inner: SecretBox::new(value),
            mode: ZeroizeMode::Safe,
        }
    }

    #[inline(always)]
    pub fn expose(&self) -> &T {
        self.inner.expose_secret()
    }

    #[inline(always)]
    pub fn expose_mut(&mut self) -> &mut T {
        self.inner.expose_secret_mut()
    }
}

// Zeroize overrides
#[cfg(feature = "zeroize")]
impl Zeroize for SecureGate<Vec<u8>> {
    fn zeroize(&mut self) {
        match self.mode {
            ZeroizeMode::Safe => self.expose_mut().safe_wipe(),
            #[cfg(feature = "unsafe-wipe")]
            ZeroizeMode::Full => unsafe { self.expose_mut().unsafe_full_wipe() },
            ZeroizeMode::Passthrough => {}
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for SecureGate<String> {
    fn zeroize(&mut self) {
        match self.mode {
            ZeroizeMode::Safe => self.expose_mut().safe_wipe(),
            #[cfg(feature = "unsafe-wipe")]
            ZeroizeMode::Full => unsafe { self.expose_mut().unsafe_full_wipe() },
            ZeroizeMode::Passthrough => {}
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> ZeroizeOnDrop for SecureGate<T> {}

// ──────────────────────────────────────────────────────────────
// Shared impls (zeroize + non-zeroize)
// ──────────────────────────────────────────────────────────────

#[cfg(feature = "zeroize")]
impl<T: Zeroize + ?Sized> Debug for SecureGate<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for SecureGate<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.expose().clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for SecureGate<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> SecureGate<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self {
            inner: SecretBox::init_with(ctr),
            mode: ZeroizeMode::Safe,
        }
    }

    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        SecretBox::try_init_with(ctr).map(|inner| Self {
            inner,
            mode: ZeroizeMode::Safe,
        })
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> SecureGate<T> {
    pub fn init_with_mut(ctr: impl FnOnce(&mut T)) -> Self {
        Self {
            inner: SecretBox::init_with_mut(ctr),
            mode: ZeroizeMode::Safe,
        }
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> SecureGate<T> {
    pub fn into_inner(mut self) -> Box<T> {
        let value = self.expose().clone();
        self.inner.zeroize();
        Box::new(value)
    }
}

// Serde
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

// finish_mut – shared
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

// ──────────────────────────────────────────────────────────────
// Fallback path – zeroize disabled
// ──────────────────────────────────────────────────────────────

#[cfg(not(feature = "zeroize"))]
pub struct SecureGate<T: ?Sized>(Box<T>);

#[cfg(not(feature = "zeroize"))]
impl<T: Sized> SecureGate<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> SecureGate<T> {
    #[inline]
    pub fn new_unsized(value: Box<T>) -> Self {
        Self(value)
    }

    #[inline]
    pub fn expose(&self) -> &T {
        &self.0
    }

    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> Debug for SecureGate<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secure<[REDACTED]>")
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Clone> Clone for SecureGate<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(not(feature = "zeroize"))]
impl<T: Default + Sized> Default for SecureGate<T> {
    fn default() -> Self {
        Self::new(T::default())
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

#[cfg(not(feature = "zeroize"))]
impl<T: ?Sized> SecureGate<T> {
    pub fn into_inner(self) -> Box<T> {
        self.0
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
