extern crate alloc;

use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::TryRngCore;

#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]

/// Helper function to try decoding a string as bech32, hex, or base64 in priority order.
#[cfg(feature = "serde-deserialize")]
fn try_decode(s: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
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
impl<T> Dynamic<Vec<T>> {}

// Macro-generated constructor implementations
crate::impl_from_dynamic!(box);
crate::impl_from_dynamic!(slice);
crate::impl_from_dynamic!(str);
crate::impl_from_dynamic!(value);

// Macro-generated hash equality implementations
crate::impl_hash_eq_dynamic!(Vec<u8>, as_slice);
crate::impl_hash_eq_dynamic!(String, as_bytes);

// Macro-generated implementations
crate::impl_ct_eq_dynamic!(Dynamic<String>, as_bytes);
crate::impl_ct_eq_dynamic!(Dynamic<Vec<u8>>, as_slice);

crate::impl_redacted_debug!(Dynamic<T>, ?Sized);

// Macro-generated constructor implementations
crate::impl_from_random_dynamic!(Dynamic<Vec<u8>>);

// Serde deserialization for Dynamic<Vec<u8>> with auto-decoding, and simple delegation for others
#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for Dynamic<alloc::vec::Vec<u8>> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use alloc::fmt;
        use serde::de::{self, Visitor};

        struct DynamicVecVisitor;

        impl<'de> Visitor<'de> for DynamicVecVisitor {
            type Value = Dynamic<alloc::vec::Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a hex/base64/bech32 string or byte vector")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let bytes = try_decode(v).map_err(E::custom)?;
                Ok(Dynamic::new(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(DynamicVecVisitor)
        } else {
            let vec: alloc::vec::Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            Ok(Dynamic::new(vec))
        }
    }
}

crate::impl_zeroize_integration_dynamic!(Dynamic<T>);
