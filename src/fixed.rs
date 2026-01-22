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
/// let secret = Fixed::new([42u8; 1]);
/// assert_eq!(secret.expose_secret()[0], 42);
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
#[cfg(feature = "rand")]
use rand::TryRngCore;

/// Helper function to try decoding a string as bech32, hex, or base64 in priority order.
#[cfg(feature = "serde-deserialize")]
fn try_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    #[cfg(feature = "encoding-bech32")]
    if let Ok((_, data)) = bech32::decode(s) {
        return Ok(data);
    }
    #[cfg(feature = "encoding-hex")]
    if let Ok(data) = hex::decode(s) {
        return Ok(data);
    }
    #[cfg(feature = "encoding-base64")]
    if let Ok(data) = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s) {
        return Ok(data);
    }
    Err("invalid encoding")
}

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

/// Custom serde deserialization for byte arrays with auto-detection of hex/base64/bech32 strings.
#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for Fixed<[u8; N]> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct FixedVisitor<const M: usize>;

        impl<'de, const M: usize> Visitor<'de> for FixedVisitor<M> {
            type Value = Fixed<[u8; M]>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "a hex/base64/bech32 string or byte array of length {}",
                    M
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = try_decode(v).map_err(E::custom)?;
                if bytes.len() != M {
                    return Err(E::invalid_length(bytes.len(), &M.to_string().as_str()));
                }
                let mut arr = [0u8; M];
                arr.copy_from_slice(&bytes);
                Ok(Fixed::new(arr))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(FixedVisitor::<N>)
        } else {
            let vec: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            if vec.len() != N {
                return Err(serde::de::Error::invalid_length(
                    vec.len(),
                    &N.to_string().as_str(),
                ));
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(&vec);
            Ok(Fixed::new(arr))
        }
    }
}
/// # Byte-array specific helpers
impl<const N: usize> Fixed<[u8; N]> {}

// Macro-generated From constructor implementations
crate::impl_from_fixed!(slice);
crate::impl_from_fixed!(array);
crate::impl_from_random_fixed!();

// Macro-generated equality implementations
crate::impl_ct_eq_fixed!();

// Optional Hash impl for collections (use HashEq for explicit equality checks)
#[cfg(feature = "hash-eq")]
impl<T: AsRef<[u8]>> core::hash::Hash for Fixed<T> {
    /// WARNING: Using Fixed in HashMap/HashSet enables implicit equality via hash collisions.
    /// This is probabilistic and NOT cryptographically secure. Prefer HashEq::hash_eq() for secrets.
    /// Rate-limit or avoid in untrusted contexts due to DoS potential.
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        use blake3::hash;
        let hash_bytes = *hash(self.inner.as_ref()).as_bytes();
        hash_bytes.hash(state);
    }
}

// Macro-generated redacted debug implementations
crate::impl_redacted_debug!(Fixed<T>);

// Serde deserialization for generic Fixed<T> (simple delegation)

// Macro-generated zeroize implementations
crate::impl_zeroize_integration_fixed!(Fixed<T>);
