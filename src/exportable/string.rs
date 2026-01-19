extern crate alloc;

#[cfg(feature = "hash-eq")]
use blake3::hash;

use crate::ExposeSecret;

/// Inner wrapper for a string that enables opt-in serialization.
///
/// This struct wraps a `String` and provides secure serialization when the
/// `SerializableSecret` marker is implemented. It ensures zeroization on drop
/// to prevent memory leaks.
use ::zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ExportableStringInner(pub alloc::string::String);

#[cfg(not(feature = "zeroize"))]
pub struct ExportableStringInner(pub alloc::string::String);

/// Debug implementation (always redacted).
impl core::fmt::Debug for ExportableStringInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Marker impl for serialization of raw strings.
impl crate::SerializableSecret for ExportableStringInner {}

/// Serde serialization support for raw strings.
#[cfg(feature = "serde-serialize")]
impl serde::Serialize for ExportableStringInner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// A string wrapped as an exportable secret for raw serialization.
///
/// This type provides a secure wrapper around a `String` that enables opt-in
/// serialization of raw text. Use this for sensitive string data like
/// passwords or tokens that need to be deliberately exported.
///
/// # Security Warning
///
/// Serializing this type exposes raw secret text. Only use in secure contexts.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "serde-serialize")]
/// # {
/// use secure_gate::ExportableString;
/// let password: ExportableString = "secret".to_string().into();
/// // password now enables serialization
/// # }
/// ```
pub type ExportableString = crate::Dynamic<ExportableStringInner>;

impl ExportableString {
    /// Construct an exportable string secret from a string.
    ///
    /// This wraps the string in a secure container for potential serialization.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::ExportableString;
    /// let secret: ExportableString = ExportableString::from("secret");
    /// # }
    /// ```
    /// Build an exportable string secret in a closure.
    ///
    /// This minimizes stack exposure by building the string temporarily.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::ExportableString;
    /// let secret = ExportableString::init_with(|| "secret".to_string());
    /// # }
    /// ```
    #[inline(always)]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> alloc::string::String,
    {
        let mut tmp = constructor();
        #[allow(unused_mut)]
        let mut result = crate::Dynamic::new(ExportableStringInner(tmp.clone()));
        #[cfg(feature = "hash-eq")]
        {
            result.eq_hash = *hash(tmp.as_bytes()).as_bytes();
        }
        #[cfg(feature = "zeroize")]
        ::zeroize::Zeroize::zeroize(&mut tmp);
        result
    }
}

impl core::convert::From<alloc::string::String> for ExportableString {
    fn from(value: alloc::string::String) -> Self {
        #[allow(unused_mut)]
        let mut s = crate::Dynamic::new(ExportableStringInner(value.clone()));
        #[cfg(feature = "hash-eq")]
        {
            s.eq_hash = *hash(value.as_bytes()).as_bytes();
        }
        s
    }
}

impl core::convert::From<&str> for ExportableString {
    fn from(value: &str) -> Self {
        #[allow(unused_mut)]
        let mut s = crate::Dynamic::new(ExportableStringInner(value.to_string()));
        #[cfg(feature = "hash-eq")]
        {
            s.eq_hash = *hash(value.as_bytes()).as_bytes();
        }
        s
    }
}

#[cfg(feature = "serde-serialize")]
impl From<crate::cloneable::CloneableString> for ExportableString {
    fn from(value: crate::cloneable::CloneableString) -> Self {
        let s = value.expose_secret().0.clone();
        #[allow(unused_mut)]
        let mut result = Self::from(s);
        #[cfg(feature = "hash-eq")]
        {
            result.eq_hash = value.eq_hash;
        }
        result
    }
}

#[cfg(feature = "serde-serialize")]
impl From<crate::Dynamic<alloc::string::String>> for ExportableString {
    fn from(value: crate::Dynamic<alloc::string::String>) -> Self {
        let crate::Dynamic {
            inner: boxed,
            eq_hash,
        } = value;
        let s = *boxed;
        #[allow(unused_mut)]
        let mut result = Self::from(s);
        #[cfg(feature = "hash-eq")]
        {
            result.eq_hash = eq_hash;
        }
        result
    }
}
