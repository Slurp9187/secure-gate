use crate::Fixed;
use zeroize::Zeroize;

/// Inner wrapper for a fixed-size array of bytes that can be safely cloned as a secret.
///
/// This struct wraps a `[u8; N]` array and implements the necessary traits for secure
/// secret handling: `Clone` for duplication and `Zeroize` for secure memory wiping.
/// The `zeroize(drop)` attribute ensures the array is zeroized when this struct is dropped.
#[derive(Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CloneableArrayInner<const N: usize>(pub [u8; N]);

impl<const N: usize> crate::CloneSafe for CloneableArrayInner<N> {}

/// A fixed-size array of bytes wrapped as a cloneable secret.
///
/// This type provides a secure wrapper around a `[u8; N]` array that can be safely cloned
/// while ensuring the underlying data is properly zeroized when no longer needed.
/// Use this for cryptographic keys, nonces, or other fixed-size secret data.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::{CloneableArray, ExposeSecret};
///
/// // Create from an array
/// let key: CloneableArray<32> = [42u8; 32].into();
///
/// // Access the inner array
/// let inner = &key.expose_secret().0;
/// assert_eq!(inner.len(), 32);
/// # }
/// ```
pub type CloneableArray<const N: usize> = Fixed<CloneableArrayInner<N>>;

impl<const N: usize> CloneableArray<N> {
    /// Construct a cloneable array secret by building it in a closure.
    ///
    /// Same stack-minimization benefits as `CloneableString::init_with`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "zeroize")]
    /// # {
    /// use secure_gate::CloneableArray;
    ///
    /// let key = CloneableArray::<32>::init_with(|| {
    ///     let mut arr = [0u8; 32];
    ///     // Fill from some source...
    ///     arr
    /// });
    /// # }
    /// ```
    #[must_use]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> [u8; N],
    {
        let mut tmp = constructor();
        let secret = Self::from(tmp);
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
        F: FnOnce() -> Result<[u8; N], E>,
    {
        let mut tmp = constructor()?;
        let secret = Self::from(tmp);
        tmp.zeroize();
        Ok(secret)
    }
}

impl<const N: usize> From<[u8; N]> for CloneableArray<N> {
    /// Wrap a `[u8; N]` array in a `CloneableArray`.
    fn from(arr: [u8; N]) -> Self {
        Fixed::new(CloneableArrayInner(arr))
    }
}
