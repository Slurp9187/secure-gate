extern crate alloc;

#[cfg(feature = "hash-eq")]
use blake3::hash;

use crate::ExposeSecret;

/// Inner wrapper for a dynamic byte vector that enables opt-in serialization.
/// This struct wraps a `Vec<u8>` and provides secure serialization when the
/// `ExportableType` marker is implemented. It ensures zeroization on drop
/// to prevent memory leaks.
#[cfg(feature = "zeroize")]
use ::zeroize::Zeroize;

#[cfg(feature = "zeroize")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ExportableVecInner(pub alloc::vec::Vec<u8>);

#[cfg(not(feature = "zeroize"))]
pub struct ExportableVecInner(pub alloc::vec::Vec<u8>);

/// Debug implementation (always redacted).
impl core::fmt::Debug for ExportableVecInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Marker impl for serialization of raw byte vectors.
impl crate::ExportableType for ExportableVecInner {}

/// Constant-time equality for raw byte vectors.
#[cfg(feature = "ct-eq")]
impl crate::ConstantTimeEq for ExportableVecInner {
    fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

/// Serde serialization support for raw byte vectors.
#[cfg(feature = "serde-serialize")]
impl serde::Serialize for ExportableVecInner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Secure encoding support for the inner vector bytes.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl crate::SecureEncoding for ExportableVecInner {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        self.0.to_hex()
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        self.0.to_hex_upper()
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        self.0.to_base64url()
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.0.to_bech32(hrp)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        self.0.to_bech32m(hrp)
    }
}

/// A dynamic byte vector wrapped as an exportable secret for raw serialization.
///
/// This type provides a secure wrapper around a `Vec<u8>` that enables opt-in
/// serialization of raw bytes. Use this for sensitive variable-size data like
/// keys or tokens that need to be deliberately exported.
///
/// # Security Warning
///
/// Serializing this type exposes raw secret bytes. Only use in secure contexts.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "serde-serialize")]
/// # {
/// use secure_gate::ExportableVec;
/// let data: ExportableVec = vec![1, 2, 3].into();
/// // data now enables serialization
/// # }
/// ```
pub type ExportableVec = crate::Dynamic<ExportableVecInner>;

impl ExportableVec {
    /// Build an exportable vec secret in a closure.
    ///
    /// This minimizes stack exposure by building the vector temporarily.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::ExportableVec;
    /// let secret = ExportableVec::init_with(|| vec![1, 2, 3]);
    /// # }
    /// ```
    #[inline(always)]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> alloc::vec::Vec<u8>,
    {
        let mut tmp = constructor();
        let result = crate::Dynamic::new(ExportableVecInner(tmp.clone()));
        #[cfg(feature = "zeroize")]
        ::zeroize::Zeroize::zeroize(&mut tmp);
        result
    }

    /// Try to build an exportable vec secret from a slice.
    ///
    /// Returns an error if the slice can't be copied into a vec.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::ExportableVec;
    /// let secret = ExportableVec::try_from_slice(&[1, 2, 3]).unwrap();
    /// # }
    /// ```
    #[inline(always)]
    pub fn try_from_slice(
        value: &[u8],
    ) -> core::result::Result<Self, alloc::collections::TryReserveError> {
        let mut vec = alloc::vec::Vec::with_capacity(value.len());
        vec.extend_from_slice(value);
        let s = crate::Dynamic::new(ExportableVecInner(vec));
        Ok(s)
    }
}

impl core::convert::From<alloc::vec::Vec<u8>> for ExportableVec {
    fn from(value: alloc::vec::Vec<u8>) -> Self {
        crate::Dynamic::new(ExportableVecInner(value.clone()))
    }
}

impl core::convert::From<&[u8]> for ExportableVec {
    fn from(value: &[u8]) -> Self {
        let inner = ExportableVecInner(value.to_vec());
        crate::Dynamic::new(inner)
    }
}

#[cfg(feature = "serde-serialize")]
impl From<crate::Dynamic<alloc::vec::Vec<u8>>> for ExportableVec {
    fn from(value: crate::Dynamic<alloc::vec::Vec<u8>>) -> Self {
        let vec = *value.inner;
        crate::Dynamic::new(ExportableVecInner(vec.clone()))
    }
}

/// Secure encoding support for the exportable vec.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl crate::SecureEncoding for ExportableVec {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> alloc::string::String {
        self.inner.0.as_slice().to_hex()
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        self.inner.0.as_slice().to_hex_upper()
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> alloc::string::String {
        self.inner.0.as_slice().to_base64url()
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32(&self, hrp: &str) -> alloc::string::String {
        self.inner.0.as_slice().to_bech32(hrp)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
        self.inner.0.as_slice().to_bech32m(hrp)
    }
}

#[cfg(feature = "serde-serialize")]
impl From<crate::cloneable::CloneableVec> for ExportableVec {
    fn from(value: crate::cloneable::CloneableVec) -> Self {
        let vec = value.expose_secret().0.clone();
        crate::Dynamic::new(ExportableVecInner(vec))
    }
}
