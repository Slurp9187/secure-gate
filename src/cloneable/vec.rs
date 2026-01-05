use crate::Dynamic;
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CloneableVecInner(Vec<u8>);

#[cfg(feature = "zeroize")]
impl crate::CloneableSecret for CloneableVecInner {}

#[cfg(feature = "zeroize")]
pub type CloneableVec = Dynamic<CloneableVecInner>;

#[cfg(feature = "zeroize")]
impl CloneableVec {
    #[inline(always)]
    pub const fn expose_inner(&self) -> &Vec<u8> {
        &self.expose_secret().0
    }

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
    #[must_use]
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
