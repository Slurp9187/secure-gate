#[cfg(feature = "rand")]
use rand::TryRngCore;

#[cfg(feature = "hash-eq")]
use crate::traits::HashEqSecret;

use crate::traits::secure_construction::Sealed as SecureSealed;

#[cfg(any(feature = "serde-deserialize", feature = "serde-serialize"))]
use serde::Deserialize;

/// Stack-allocated secure secret wrapper.
///
/// This is a zero-cost wrapper for fixed-size secrets like byte arrays or primitives.
/// The inner field is private, forcing all access through explicit methods.
///
/// Security invariants:
/// - No `Deref` or `AsRef` — prevents silent access or borrowing.
/// - No implicit `Copy` — even for `[u8; N]`, duplication must be explicit via `.clone()`.
/// - `Debug` is always redacted.
///
/// # Examples
///
/// Basic usage:
/// ```
/// use secure_gate::{Fixed, ExposeSecret};
/// let secret = Fixed::new(42u32);
/// assert_eq!(*secret.expose_secret(), 42);
/// ```
///
/// For byte arrays (most common):
/// ```
/// use secure_gate::{fixed_alias, Fixed, ExposeSecret};
/// fixed_alias!(Aes256Key, 32);
/// let key_bytes = [0x42u8; 32];
/// let key: Aes256Key = Fixed::from(key_bytes);
/// assert_eq!(key.len(), 32);
/// assert_eq!(key.expose_secret()[0], 0x42);
/// ```
///
/// With `zeroize` feature (automatic wipe on drop):
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::Fixed;
/// let mut secret = Fixed::new([1u8, 2, 3]);
/// drop(secret); // memory wiped automatically
/// # }
/// ```
pub struct Fixed<T> {
    pub(crate) inner: T,
}

impl<T> Fixed<T> {
    /// Wrap a value in a `Fixed` secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// Wrap a value in a Fixed secret.
    ///
    /// This is zero-cost and const-friendly.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// const SECRET: Fixed<u32> = Fixed::new(42);
    /// ```
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Fixed { inner: value }
    }
}

/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

impl<const N: usize> From<&[u8]> for Fixed<[u8; N]> {
    /// Create a `Fixed` from a byte slice, panicking on length mismatch.
    ///
    /// This is a fail-fast conversion for crypto contexts where exact length is expected.
    /// Panics if the slice length does not match the array size `N`.
    ///
    /// # Panics
    ///
    /// Panics if `slice.len() != N`.
    fn from(slice: &[u8]) -> Self {
        assert_eq!(
            slice.len(),
            N,
            "slice length mismatch: expected {}, got {}",
            N,
            slice.len()
        );
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Self::new(arr)
    }
}

impl<const N: usize> From<[u8; N]> for Fixed<[u8; N]> {
    /// Wrap a raw byte array in a `Fixed` secret.
    ///
    /// Zero-cost conversion.
    ///
    /// Wrap a raw byte array in a Fixed secret.
    ///
    /// Zero-cost conversion.
    ///
    /// # Example
    ///
    /// ```
    /// use secure_gate::Fixed;
    /// let key: Fixed<[u8; 4]> = [1, 2, 3, 4].into();
    /// ```
    #[inline(always)]
    fn from(arr: [u8; N]) -> Self {
        Self::new(arr)
    }
}

crate::impl_redacted_debug!(Fixed<T>);

/// On-demand hash equality.
#[cfg(feature = "hash-eq")]
impl<T> crate::traits::hash_eq::Sealed for Fixed<T> {}

#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> crate::HashEqSecret for Fixed<T> {
    fn hash_digest(&self) -> [u8; 32] {
        use blake3::hash;
        *hash(self.inner.as_ref()).as_bytes()
    }
}

#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> PartialEq for Fixed<T> {
    fn eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.hash_digest().ct_eq(&other.hash_digest())
    }
}

#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> Eq for Fixed<T> {}

#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> core::hash::Hash for Fixed<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.hash_digest().hash(state);
    }
}

#[cfg(feature = "ct-eq")]
use crate::ExposeSecret;

/// Constant-time equality — only available with `ct-eq` feature.
#[cfg(feature = "ct-eq")]
impl<const N: usize> Fixed<[u8; N]> {
    /// Constant-time equality comparison.
    ///
    /// This is the **only safe way** to compare two fixed-size secrets.
    /// Available only when the `ct-eq` feature is enabled.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "ct-eq")]
    /// # {
    /// use secure_gate::Fixed;
    /// let a = Fixed::new([1u8; 32]);
    /// let b = Fixed::new([1u8; 32]);
    /// assert!(a.ct_eq(&b));
    /// # }
    /// ```
    #[inline]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use crate::traits::ConstantTimeEq;
        self.expose_secret().ct_eq(other.expose_secret())
    }
}

/// Secure construction — only available with relevant features.
impl<const N: usize> SecureSealed for Fixed<[u8; N]> {}

#[cfg(any(
    feature = "rand",
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<const N: usize> crate::SecureConstruction for Fixed<[u8; N]> {
    #[cfg(feature = "rand")]
    fn from_random() -> Self {
        let mut bytes = [0u8; N];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OsRng failure is a program error");
        Self::from(bytes)
    }

    #[cfg(feature = "encoding-hex")]
    fn from_hex(s: &str) -> Self {
        use hex as hex_crate;
        let decoded = hex_crate::decode(s).expect("invalid hex string");
        if decoded.len() != N {
            panic!(
                "hex decode length mismatch: expected {}, got {}",
                N,
                decoded.len()
            );
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&decoded);
        Self::from(arr)
    }

    #[cfg(feature = "encoding-base64")]
    fn from_base64(s: &str) -> Self {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let decoded = URL_SAFE_NO_PAD.decode(s).expect("invalid base64 string");
        if decoded.len() != N {
            panic!(
                "base64 decode length mismatch: expected {}, got {}",
                N,
                decoded.len()
            );
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&decoded);
        Self::from(arr)
    }

    #[cfg(feature = "encoding-bech32")]
    fn from_bech32(s: &str, hrp: &str) -> Self {
        use bech32::decode;
        let (decoded_hrp, decoded_data) = decode(s).expect("invalid bech32 string");
        if decoded_hrp.as_str() != hrp {
            panic!(
                "bech32 HRP mismatch: expected {}, got {}",
                hrp,
                decoded_hrp.as_str()
            );
        }
        if decoded_data.len() != N {
            panic!(
                "bech32 decode length mismatch: expected {}, got {}",
                N,
                decoded_data.len()
            );
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&decoded_data);
        Self::from(arr)
    }
}

/// Zeroize integration.
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::Zeroize for Fixed<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

/// Zeroize on drop integration.
#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize> zeroize::ZeroizeOnDrop for Fixed<T> {}

/// Serde deserialization support (unconditional; requires serde-deserialize feature).
#[cfg(feature = "serde-deserialize")]
impl<'de, T> Deserialize<'de> for Fixed<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Fixed::new(inner))
    }
}
