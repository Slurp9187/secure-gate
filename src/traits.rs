use crate::{Dynamic, Fixed};

#[cfg(feature = "rand")]
use crate::random::{DynamicRandom, FixedRandom};

#[cfg(feature = "zeroize")]
use crate::cloneable::{CloneableArray, CloneableString, CloneableVec};

#[cfg(feature = "encoding-hex")]
use crate::encoding::hex::HexString;

#[cfg(feature = "encoding-base64")]
use crate::encoding::base64::Base64String;

#[cfg(feature = "encoding-bech32")]
use crate::encoding::bech32::Bech32String;

pub trait ExposeSecretReadOnly {
    type Inner: ?Sized;

    fn expose_secret(&self) -> &Self::Inner;
}

pub trait ExposeSecret: ExposeSecretReadOnly {
    fn expose_secret_mut(&mut self) -> &mut Self::Inner;
}

// Core wrappers — full read + mut
impl<T> ExposeSecretReadOnly for Fixed<T> {
    type Inner = T;
    #[inline(always)]
    fn expose_secret(&self) -> &T {
        self.expose_secret()
    }
}

impl<T> ExposeSecret for Fixed<T> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }
}

impl<T: ?Sized> ExposeSecretReadOnly for Dynamic<T> {
    type Inner = T;
    #[inline(always)]
    fn expose_secret(&self) -> &T {
        self.expose_secret()
    }
}

impl<T: ?Sized> ExposeSecret for Dynamic<T> {
    #[inline(always)]
    fn expose_secret_mut(&mut self) -> &mut T {
        self.expose_secret_mut()
    }
}

// Random — read-only only (preserve freshness)
#[cfg(feature = "rand")]
impl<const N: usize> ExposeSecretReadOnly for FixedRandom<N> {
    type Inner = [u8];
    #[inline(always)]
    fn expose_secret(&self) -> &[u8] {
        self.expose_secret()
    }
}

#[cfg(feature = "rand")]
impl ExposeSecretReadOnly for DynamicRandom {
    type Inner = [u8];
    #[inline(always)]
    fn expose_secret(&self) -> &[u8] {
        self.expose_secret()
    }
}

// Encoding — read-only only (preserve validation/canonical form)
#[cfg(feature = "encoding-hex")]
impl ExposeSecretReadOnly for HexString {
    type Inner = str;
    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}

#[cfg(feature = "encoding-base64")]
impl ExposeSecretReadOnly for Base64String {
    type Inner = str;
    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}

#[cfg(feature = "encoding-bech32")]
impl ExposeSecretReadOnly for Bech32String {
    type Inner = str;
    #[inline(always)]
    fn expose_secret(&self) -> &str {
        self.expose_secret().0.as_str()
    }
}

pub trait SecureMetadata {
    fn len(&self) -> usize;

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// SecureMetadata impls
impl<const N: usize> SecureMetadata for Fixed<[u8; N]> {
    fn len(&self) -> usize {
        N
    }
}

impl SecureMetadata for Dynamic<String> {
    fn len(&self) -> usize {
        self.len()
    }
}

impl<T> SecureMetadata for Dynamic<Vec<T>> {
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "rand")]
impl<const N: usize> SecureMetadata for FixedRandom<N> {
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "rand")]
impl SecureMetadata for DynamicRandom {
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "encoding-hex")]
impl SecureMetadata for HexString {
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "encoding-base64")]
impl SecureMetadata for Base64String {
    fn len(&self) -> usize {
        self.len()
    }
}

#[cfg(feature = "encoding-bech32")]
impl SecureMetadata for Bech32String {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> SecureMetadata for CloneableArray<N> {
    fn len(&self) -> usize {
        N
    }
}

#[cfg(feature = "zeroize")]
impl SecureMetadata for CloneableString {
    fn len(&self) -> usize {
        self.expose_inner().len()
    }
}

#[cfg(feature = "zeroize")]
impl SecureMetadata for CloneableVec {
    fn len(&self) -> usize {
        self.expose_inner().len()
    }
}

#[cfg(feature = "rand")]
pub trait SecureRandom: ExposeSecretReadOnly<Inner = [u8]> + SecureMetadata {}

#[cfg(feature = "rand")]
impl<const N: usize> SecureRandom for FixedRandom<N> {}

#[cfg(feature = "rand")]
impl SecureRandom for DynamicRandom {}
