use crate::Dynamic;
use zeroize::Zeroize;

/// Inner wrapper for a string that can be safely cloned as a secret.
///
/// This struct wraps a `String` and implements the necessary traits for secure
/// secret handling: `Clone` for duplication and `Zeroize` for secure memory wiping.
/// The `zeroize(drop)` attribute ensures the string contents are zeroized when
/// this struct is dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct CloneableStringInner(String);

impl crate::CloneSafe for CloneableStringInner {}

/// A string wrapped as a cloneable secret.
///
/// This type provides a secure wrapper around a `String` that can be safely cloned
/// while ensuring the underlying data is properly zeroized when no longer needed.
/// Use this for sensitive text data like passwords, tokens, or cryptographic passphrases.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "zeroize")]
/// # {
/// use secure_gate::CloneableString;
///
/// // Create from a string
/// let password: CloneableString = "secret123".to_string().into();
///
/// // Create from a string slice
/// let token: CloneableString = "token_value".into();
///
/// // Access the inner string
/// let inner = password.expose_inner();
/// assert_eq!(inner.as_str(), "secret123");
/// # }
/// ```
pub type CloneableString = Dynamic<CloneableStringInner>;

impl CloneableString {
    /// Returns a reference to the inner string without cloning.
    ///
    /// This method provides direct access to the wrapped `String`.
    /// The reference is valid for the lifetime of the `CloneableString`.
    #[inline(always)]
    pub const fn expose_inner(&self) -> &String {
        &self.expose_secret().0
    }

    /// Returns a mutable reference to the inner string.
    ///
    /// This method provides direct mutable access to the wrapped `String`.
    /// Use this when you need to modify the string contents in-place.
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
    /// Same stack-minimization benefits as `init_with`, but allows for construction
    /// that may fail with an error. Useful when reading secrets from fallible sources
    /// like files, network connections, or user input that may encounter I/O errors.
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

/// Wrap a `String` in a `CloneableString`.
impl From<String> for CloneableString {
    fn from(value: String) -> Self {
        Dynamic::new(CloneableStringInner(value))
    }
}

/// Wrap a string slice in a `CloneableString`.
impl From<&str> for CloneableString {
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}
