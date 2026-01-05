use crate::Dynamic;
use zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CloneableStringInner(String);

#[cfg(feature = "zeroize")]
impl crate::CloneableSecret for CloneableStringInner {}

#[cfg(feature = "zeroize")]
pub type CloneableString = Dynamic<CloneableStringInner>;

#[cfg(feature = "zeroize")]
impl CloneableString {
    #[inline(always)]
    pub const fn expose_inner(&self) -> &String {
        &self.expose_secret().0
    }

    #[inline(always)]
    pub fn expose_inner_mut(&mut self) -> &mut String {
        &mut self.expose_secret_mut().0
    }
}

#[cfg(feature = "zeroize")]
impl From<String> for CloneableString {
    fn from(value: String) -> Self {
        Dynamic::new(CloneableStringInner(value))
    }
}

#[cfg(feature = "zeroize")]
impl From<&str> for CloneableString {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}
