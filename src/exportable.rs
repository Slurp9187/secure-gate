//! Exportable types for opt-in raw secret serialization.
//!
//! These types allow deliberate serialization of raw secrets (bytes/text) via serde,
//! with automatic zeroization on drop to prevent lingering sensitive data.
//!
//! Requires the `"serde-serialize"` feature for `Serialize` impls.
//! Requires the `"serde-deserialize"` feature for `Deserialize` impls.
//!
//! # Security
//!
//! Only use these types for trusted, secure contexts (e.g., encrypted storage).
//! Raw serialization can expose secrets—audit all usages.

use alloc::string::String;
use alloc::vec::Vec;

/// Exportable wrapper for fixed-size byte arrays.
///
/// Serializes as a JSON array of bytes, deserializes from same.
/// Zeroizes the array on drop.
#[derive(Clone)]
pub struct ExportableArray<const N: usize> {
    inner: [u8; N],
}

#[cfg(feature = "serde-serialize")]
impl<const N: usize> serde::Serialize for ExportableArray<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde-deserialize")]
impl<'de, const N: usize> serde::Deserialize<'de> for ExportableArray<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        let len = vec.len();
        let inner: [u8; N] = vec.try_into().map_err(|_| {
            serde::de::Error::custom(format!("expected array of length {}, got {}", N, len))
        })?;
        Ok(Self { inner })
    }
}

impl<const N: usize> ExportableArray<N> {
    /// Create from a raw array.
    pub fn new(data: [u8; N]) -> Self {
        Self { inner: data }
    }
}

impl<const N: usize> From<[u8; N]> for ExportableArray<N> {
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> zeroize::Zeroize for ExportableArray<N> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const N: usize> zeroize::ZeroizeOnDrop for ExportableArray<N> {}

/// Exportable wrapper for byte vectors.
///
/// Serializes as a JSON array of bytes, deserializes from same.
/// Zeroizes the vector on drop.
#[cfg_attr(feature = "serde-serialize", derive(serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(serde::Deserialize))]
#[derive(Clone)]
pub struct ExportableVec {
    inner: Vec<u8>,
}

impl ExportableVec {
    /// Create from a raw Vec<u8>.
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }
}

impl From<Vec<u8>> for ExportableVec {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for ExportableVec {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for ExportableVec {}

/// Exportable wrapper for strings.
///
/// Serializes as a JSON string, deserializes from same.
/// Zeroizes the string on drop.
#[cfg_attr(feature = "serde-serialize", derive(serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(serde::Deserialize))]
#[derive(Clone)]
pub struct ExportableString {
    inner: String,
}

impl ExportableString {
    /// Create from a raw String.
    pub fn new(data: String) -> Self {
        Self { inner: data }
    }
}

impl From<String> for ExportableString {
    fn from(data: String) -> Self {
        Self::new(data)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for ExportableString {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for ExportableString {}
