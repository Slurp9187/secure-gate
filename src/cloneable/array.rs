use crate::Fixed;
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CloneableArrayInner<const N: usize>([u8; N]);

#[cfg(feature = "zeroize")]
impl<const N: usize> crate::CloneableSecret for CloneableArrayInner<N> {}

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
}

#[cfg(feature = "zeroize")]
impl<const N: usize> From<[u8; N]> for CloneableArray<N> {
    fn from(arr: [u8; N]) -> Self {
        Fixed::new(CloneableArrayInner(arr))
    }
}
