extern crate alloc;

use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::TryRngCore;

#[cfg(feature = "hash-eq")]
use crate::traits::HashEqSecret;

/// Heap-allocated secure secret wrapper.
///
/// This is a thin wrapper around `Box<T>` with enforced explicit exposure.
/// Suitable for dynamic-sized secrets like `String` or `Vec<u8>`.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access.
/// - `Debug` is always redacted.
/// - With `zeroize`, wipes the entire allocation on drop (including spare capacity).
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let secret: Dynamic<String> = "hunter2".into();
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// With already-boxed values:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret};
/// let boxed_secret = Box::new("hunter2".to_string());
/// let secret: Dynamic<String> = boxed_secret.into(); // or Dynamic::from(boxed_secret)
/// assert_eq!(secret.expose_secret(), "hunter2");
/// ```
///
/// Mutable access:
/// ```
/// use secure_gate::{Dynamic, ExposeSecret, ExposeSecretMut};
/// let mut secret = Dynamic::<String>::new("pass".to_string());
/// secret.expose_secret_mut().push('!');
/// assert_eq!(secret.expose_secret(), "pass!");
/// ```
///
/// With `zeroize` (automatic wipe):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Dynamic;
/// let secret = Dynamic::<Vec<u8>>::new(vec![1u8; 32]);
/// drop(secret); // heap wiped automatically
/// # }
/// ```
pub struct Dynamic<T: ?Sized> {
    pub(crate) inner: Box<T>,
}

impl<T: ?Sized> Dynamic<T> {
    /// Wrap a value by boxing it.
    ///
    /// Uses `Into<Box<T>>` for flexibility.
    #[inline(always)]
    pub fn new<U>(value: U) -> Self
    where
        U: Into<Box<T>>,
    {
        let inner = value.into();
        Self { inner }
    }
}

/// # Ergonomic helpers for common heap types
impl Dynamic<String> {}

/// On-demand hash equality.
#[cfg(feature = "hash-eq")]
impl<T: ?Sized> crate::traits::hash_eq::Sealed for Dynamic<T> {}

#[cfg(feature = "hash-eq")]
impl crate::HashEqSecret for Dynamic<Vec<u8>> {
    fn hash_digest(&self) -> [u8; 32] {
        use blake3::hash;
        *hash(self.inner.as_slice()).as_bytes()
    }
}

#[cfg(feature = "hash-eq")]
impl crate::HashEqSecret for Dynamic<String> {
    fn hash_digest(&self) -> [u8; 32] {
        use blake3::hash;
        *hash(self.inner.as_bytes()).as_bytes()
    }
}

#[cfg(feature = "hash-eq")]
impl PartialEq for Dynamic<Vec<u8>> {
    fn eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.hash_digest().ct_eq(&other.hash_digest())
    }
}

#[cfg(feature = "hash-eq")]
impl Eq for Dynamic<Vec<u8>> {}

#[cfg(feature = "hash-eq")]
impl core::hash::Hash for Dynamic<Vec<u8>> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.hash_digest().hash(state);
    }
}

#[cfg(feature = "hash-eq")]
impl PartialEq for Dynamic<String> {
    fn eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.hash_digest().ct_eq(&other.hash_digest())
    }
}

#[cfg(feature = "hash-eq")]
impl Eq for Dynamic<String> {}

#[cfg(feature = "hash-eq")]
impl core::hash::Hash for Dynamic<String> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.hash_digest().hash(state);
    }
}

/// # Additional conversions
/// Wrap a byte slice in a [`Dynamic`] [`Vec<u8>`].
impl From<&[u8]> for Dynamic<Vec<u8>> {
    #[inline(always)]
    fn from(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl<T> Dynamic<Vec<T>> {}

/// # Convenient From impls
/// Wrap a value in a [`Dynamic`] secret by boxing it.
impl<T: 'static> From<T> for Dynamic<T> {
    #[inline(always)]
    fn from(value: T) -> Self {
        Self {
            inner: Box::new(value),
        }
    }
}

/// Wrap a boxed value in a [`Dynamic`] secret.
impl<T: ?Sized> From<Box<T>> for Dynamic<T> {
    #[inline(always)]
    fn from(boxed: Box<T>) -> Self {
        Self { inner: boxed }
    }
}

/// Wrap a string slice in a [`Dynamic`] [`String`].
impl From<&str> for Dynamic<String> {
    #[inline(always)]
    fn from(input: &str) -> Self {
        Self::new(input.to_string())
    }
}

/// Random generation — only available with `rand` feature.
#[cfg(feature = "rand")]
impl Dynamic<Vec<u8>> {
    /// Fill with fresh random bytes of the specified length using the OS RNG.
    ///
    /// Panics on RNG failure for fail-fast crypto code. Guarantees secure entropy
    /// from system sources.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "rand")]
    /// # {
    /// use secure_gate::{Dynamic, ExposeSecret};
    /// let random: Dynamic<Vec<u8>> = Dynamic::from_random(64);
    /// assert_eq!(random.len(), 64);
    /// # }
    /// ```
    #[inline]
    pub fn from_random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }

    /// Decode from hex string to Vec<u8> (panics on invalid).
    #[cfg(feature = "encoding-hex")]
    pub fn from_hex(s: &str) -> Self {
        use hex as hex_crate;
        let decoded = hex_crate::decode(s).expect("invalid hex string");
        Self::from(decoded)
    }

    /// Decode from base64 string to Vec<u8> (panics on invalid).
    #[cfg(feature = "encoding-base64")]
    pub fn from_base64(s: &str) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let decoded = URL_SAFE_NO_PAD.decode(s).expect("invalid base64 string");
        Self::from(decoded)
    }

    /// Decode from bech32 string with HRP to Vec<u8> (panics on invalid/HRP mismatch).
    #[cfg(feature = "encoding-bech32")]
    pub fn from_bech32(s: &str, hrp: &str) -> Self {
        use bech32::decode;
        let (decoded_hrp, decoded_data) = decode(s).expect("invalid bech32 string");
        if decoded_hrp.as_str() != hrp {
            panic!(
                "bech32 HRP mismatch: expected {}, got {}",
                hrp,
                decoded_hrp.as_str()
            );
        }
        Self::from(decoded_data)
    }
}

// Macro-generated implementations
crate::impl_ct_eq_dynamic!(Dynamic<String>, as_bytes);
crate::impl_ct_eq_dynamic!(Dynamic<Vec<u8>>, as_slice);
crate::impl_redacted_debug!(Dynamic<T>, ?Sized);
crate::impl_serde_deserialize_dynamic!(Dynamic<T>);
crate::impl_zeroize_integration_dynamic!(Dynamic<T>);
