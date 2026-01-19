#[cfg(feature = "zeroize")]
use crate::Dynamic;
use zeroize::Zeroize;

/// Inner wrapper for a vector of bytes that can be safely cloned as a secret.
///
/// This struct wraps a `Vec<u8>` and implements the necessary traits for secure
/// secret handling: `Clone` for duplication and `Zeroize` for secure memory wiping.
/// The `zeroize(drop)` attribute ensures the vector contents are zeroized when
/// this struct is dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CloneableVecInner(pub Vec<u8>);

impl AsRef<[u8]> for CloneableVecInner {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl crate::CloneSafe for CloneableVecInner {}

/// Serde serialization support (serializes the vector).
/// Uniformly gated by SerializableSecret marker on inner type.
/// A dynamically-sized vector of bytes wrapped as a cloneable secret.
///
/// This type provides a secure wrapper around a `Vec<u8>` that can be safely cloned
/// while ensuring the underlying data is properly zeroized when no longer needed.
/// Use this for variable-length secret data like encrypted payloads or keys.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::{CloneableVec, ExposeSecret};
///
/// // Create from a vector
/// let data: CloneableVec = vec![1, 2, 3, 4].into();
///
/// // Create from a slice
/// let data2: CloneableVec = b"hello world".as_slice().into();
///
/// // Access the inner vector
/// let inner = &data.expose_secret().0;
/// assert_eq!(inner.len(), 4);
/// # }
/// ```
pub type CloneableVec = Dynamic<CloneableVecInner>;

impl CloneableVec {
    /// Construct a cloneable vec secret by building it in a closure.
    ///
    /// Same stack-minimization benefits as `CloneableString::init_with`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "zeroize")]
    /// # {
    /// use secure_gate::CloneableVec;
    ///
    /// let seed = CloneableVec::init_with(|| {
    ///     let mut v = vec![0u8; 32];
    ///     // Fill from some source...
    ///     v
    /// });
    /// # }
    /// ```
    #[must_use]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> Vec<u8>,
    {
        let mut tmp = constructor();
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        secret
    }

    /// Fallible version of `init_with`.
    ///
    /// Same stack-minimization benefits as `init_with`, but allows for construction
    /// that may fail with an error. Useful when reading secrets from fallible sources
    /// like files or network connections.
    pub fn try_init_with<F, E>(constructor: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<Vec<u8>, E>,
    {
        let mut tmp = constructor()?;
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        Ok(secret)
    }
}

/// Wrap a `Vec<u8>` in a `CloneableVec`.
impl From<Vec<u8>> for CloneableVec {
    fn from(value: Vec<u8>) -> Self {
        Dynamic::new(CloneableVecInner(value))
    }
}

/// Wrap a byte slice in a `CloneableVec`.
impl From<&[u8]> for CloneableVec {
    fn from(value: &[u8]) -> Self {
        Self::from(value.to_vec())
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for CloneableVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut temp: Vec<u8> = Vec::deserialize(deserializer)?;
        let secret = Self::from(temp.clone());
        temp.zeroize();
        Ok(secret)
    }
}
