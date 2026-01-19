#[cfg(feature = "zeroize")]
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
pub struct CloneableStringInner(pub String);

impl AsRef<[u8]> for CloneableStringInner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

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
/// use secure_gate::{CloneableString, ExposeSecret};
///
/// // Create from a string
/// let password: CloneableString = "secret123".to_string().into();
///
/// // Create from a string slice
/// let token: CloneableString = "token_value".into();
///
/// // Access the inner string
/// assert_eq!(password.expose_secret().0.as_str(), "secret123");
/// # }
/// ```
pub type CloneableString = Dynamic<CloneableStringInner>;

impl CloneableString {
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

impl From<&str> for CloneableString {
    fn from(s: &str) -> Self {
        let inner = CloneableStringInner(s.to_string());
        #[allow(unused_mut)]
        let mut secret = Dynamic::new(inner);
        #[cfg(feature = "hash-eq")]
        {
            use blake3::hash;
            secret.eq_hash = *hash(s.as_bytes()).as_bytes();
        }
        secret
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de> serde::Deserialize<'de> for CloneableString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut temp: String = String::deserialize(deserializer)?;
        let secret = Self::from(temp.clone());
        temp.zeroize();
        Ok(secret)
    }
}
