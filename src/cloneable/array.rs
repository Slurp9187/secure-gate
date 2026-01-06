use crate::Fixed;
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CloneableArrayInner<const N: usize>([u8; N]);

#[cfg(feature = "zeroize")]
impl<const N: usize> crate::CloneableSecretMarker for CloneableArrayInner<N> {}

#[cfg(feature = "zeroize")]
pub type CloneableArray<const N: usize> = Fixed<CloneableArrayInner<N>>;

#[cfg(feature = "zeroize")]
impl<const N: usize> CloneableArray<N> {
    #[inline(always)]
    pub const fn expose_inner(&self) -> &[u8; N] {
        &self.expose_secret().0
    }

    #[inline(always)]
    pub fn expose_inner_mut(&mut self) -> &mut [u8; N] {
        &mut self.expose_secret_mut().0
    }

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
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        secret
    }

    /// Fallible version of `init_with`.
    pub fn try_init_with<F, E>(constructor: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<[u8; N], E>,
    {
        let mut tmp = constructor()?;
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        Ok(secret)
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> From<[u8; N]> for CloneableArray<N> {
    fn from(arr: [u8; N]) -> Self {
        Fixed::new(CloneableArrayInner(arr))
    }
}
