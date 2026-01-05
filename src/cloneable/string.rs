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

    /// Construct a cloneable string secret by building it in a closure.
    ///
    /// This minimizes the time the secret spends on the stack:
    /// - The closure builds a temporary `String`.
    /// - It is immediately cloned to the heap.
    /// - The temporary is zeroized before returning.
    ///
    /// Use this when reading passwords or tokens from user input.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "zeroize")]
    /// # {
    /// use secure_gate::CloneableString;
    /// use std::io::{self, Write};
    ///
    /// fn read_password() -> io::Result<String> {
    ///     let mut input = String::new();
    ///     io::stdout().flush()?;
    ///     io::stdin().read_line(&mut input)?;
    ///     Ok(input.trim_end().to_string())
    /// }
    ///
    /// let pw = CloneableString::init_with(|| read_password().unwrap());
    /// # }
    /// ```
    #[must_use]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> String,
    {
        let mut tmp = constructor();
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        secret
    }

    /// Fallible version of `init_with`.
    ///
    /// Useful when construction can fail (e.g., I/O errors).
    #[must_use]
    pub fn try_init_with<F, E>(constructor: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<String, E>,
    {
        let mut tmp = constructor()?;
        let secret = Self::from(tmp.clone());
        tmp.zeroize();
        Ok(secret)
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
