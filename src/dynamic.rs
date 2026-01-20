extern crate alloc;

use alloc::boxed::Box;

#[cfg(feature = "rand")]
use rand::TryRngCore;

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

// Macro-generated constructor implementations
crate::impl_from_random!(Dynamic<Vec<u8>>);
crate::impl_from_hex!(Dynamic<Vec<u8>>);
crate::impl_from_base64!(Dynamic<Vec<u8>>);
crate::impl_from_bech32!(Dynamic<Vec<u8>>);

// Macro-generated implementations
crate::impl_ct_eq_dynamic!(Dynamic<String>, as_bytes);
crate::impl_ct_eq_dynamic!(Dynamic<Vec<u8>>, as_slice);

crate::impl_redacted_debug!(Dynamic<T>, ?Sized);
crate::impl_serde_deserialize_dynamic!(Dynamic<T>);
crate::impl_zeroize_integration_dynamic!(Dynamic<T>);
