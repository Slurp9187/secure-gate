use crate::Dynamic;
use zeroize::Zeroize;

/// Inner wrapper for a vector of bytes that can be safely cloned as a secret.
///
/// This struct wraps a `Vec<u8>` and implements the necessary traits for secure
/// secret handling: `Clone` for duplication and `Zeroize` for secure memory wiping.
/// The `zeroize(drop)` attribute ensures the vector contents are zeroized when
/// this struct is dropped.
#[cfg(feature = "zeroize")]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CloneableVecInner(Vec<u8>);

#[cfg(feature = "zeroize")]
impl crate::CloneableSecretMarker for CloneableVecInner {}

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
/// use secure_gate::CloneableVec;
///
/// // Create from a vector
/// let data: CloneableVec = vec![1, 2, 3, 4].into();
///
/// // Create from a slice
/// let data2: CloneableVec = b"hello world".as_slice().into();
///
/// // Access the inner vector
/// let inner = data.expose_inner();
/// assert_eq!(inner.len(), 4);
/// # }
/// ```
#[cfg(feature = "zeroize")]
pub type CloneableVec = Dynamic<CloneableVecInner>;

#[cfg(feature = "zeroize")]
impl CloneableVec {
    /// Returns a reference to the inner vector without cloning.
    ///
    /// This method provides direct access to the wrapped `Vec<u8>`.
    /// The reference is valid for the lifetime of the `CloneableVec`.
    #[inline(always)]
    pub const fn expose_inner(&self) -> &Vec<u8> {
        &self.expose_secret().0
    }

    /// Returns a mutable reference to the inner vector.
    ///
    /// This method provides direct mutable access to the wrapped `Vec<u8>`.
    /// Use this when you need to modify the vector contents in-place.
    #[inline(always)]
    pub fn expose_inner_mut(&mut self) -> &mut Vec<u8> {
        &mut self.expose_secret_mut().0
    }

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

#[cfg(feature = "zeroize")]
impl From<Vec<u8>> for CloneableVec {
    fn from(value: Vec<u8>) -> Self {
        Dynamic::new(CloneableVecInner(value))
    }
}

#[cfg(feature = "zeroize")]
impl From<&[u8]> for CloneableVec {
    fn from(value: &[u8]) -> Self {
        Self::from(value.to_vec())
    }
}
