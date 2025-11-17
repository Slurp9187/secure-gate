// src/stack.rs
//
// Zero-allocation, stack-only secret types

#[cfg(feature = "zeroize")]
use core::fmt::{self, Debug};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "zeroize")]
use crate::{ExposeSecret, ExposeSecretMut};

/// Stack-allocated secure wrapper: `Zeroizing<T>` (zeroize only; fixed-size T like [u8; N]).
#[cfg(feature = "zeroize")]
pub struct StackSecure<T: Zeroize + Sized>(Zeroizing<T>);

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> StackSecure<T> {
    /// Create from value.
    #[inline]
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> StackSecure<T> {
    /// Expose immutable reference.
    #[inline]
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Expose mutable reference.
    #[inline]
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> Debug for StackSecure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StackSecure<[REDACTED]>")
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> ExposeSecret<T> for StackSecure<T> {
    fn expose_secret(&self) -> &T {
        self.expose()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> ExposeSecretMut<T> for StackSecure<T> {
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Clone + Zeroize + Sized> Clone for StackSecure<T> {
    fn clone(&self) -> Self {
        Self::new(self.expose().clone())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Default + Zeroize + Sized> Default for StackSecure<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> Zeroize for StackSecure<T> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> ZeroizeOnDrop for StackSecure<T> {}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> core::ops::Deref for StackSecure<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.expose()
    }
}

#[cfg(feature = "zeroize")]
impl<T: Zeroize + Sized> core::ops::DerefMut for StackSecure<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.expose_mut()
    }
}

#[cfg(feature = "zeroize")]
macro_rules! impl_from_array {
    ($($N:literal),*) => {$(
        impl From<[u8; $N]> for StackSecure<[u8; $N]> {
            fn from(arr: [u8; $N]) -> Self { Self::new(arr) }
        }
    )*}
}
#[cfg(feature = "zeroize")]
impl_from_array!(12, 16, 24, 32, 64);

#[cfg(feature = "zeroize")]
impl<const N: usize> AsRef<[u8]> for StackSecure<[u8; N]> {
    fn as_ref(&self) -> &[u8] {
        self.expose().as_ref()
    }
}

// Aliases and constructors
#[cfg(feature = "zeroize")]
pub type Key32 = StackSecure<[u8; 32]>;
#[cfg(feature = "zeroize")]
pub type Key64 = StackSecure<[u8; 64]>;
#[cfg(feature = "zeroize")]
pub type Nonce12 = StackSecure<[u8; 12]>;
#[cfg(feature = "zeroize")]
pub type Nonce16 = StackSecure<[u8; 16]>;
#[cfg(feature = "zeroize")]
pub type Nonce24 = StackSecure<[u8; 24]>;
#[cfg(feature = "zeroize")]
pub type Iv = StackSecure<[u8; 16]>;
#[cfg(feature = "zeroize")]
pub type Salt = StackSecure<[u8; 16]>;

#[cfg(feature = "zeroize")]
macro_rules! new_fn {
    ($name:ident, $size:expr) => {
        #[must_use]
        pub fn $name(bytes: [u8; $size]) -> StackSecure<[u8; $size]> {
            StackSecure::new(bytes)
        }
    };
}

#[cfg(feature = "zeroize")]
new_fn!(key32, 32);
#[cfg(feature = "zeroize")]
new_fn!(key64, 64);
#[cfg(feature = "zeroize")]
new_fn!(nonce12, 12);
#[cfg(feature = "zeroize")]
new_fn!(nonce16, 16);
#[cfg(feature = "zeroize")]
new_fn!(nonce24, 24);
#[cfg(feature = "zeroize")]
new_fn!(iv, 16);
#[cfg(feature = "zeroize")]
new_fn!(salt, 16);
