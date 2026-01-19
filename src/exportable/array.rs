/// Inner wrapper for a fixed-size byte array that enables opt-in serialization.
///
/// This struct wraps a byte array and provides secure serialization when the
/// `SerializableSecret` marker is implemented. It ensures zeroization on drop
/// to prevent memory leaks.
#[cfg(feature = "zeroize")]
use ::zeroize::Zeroize;

use crate::ExposeSecret;

#[cfg(feature = "zeroize")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ExportableArrayInner<const N: usize>(pub [u8; N]);

#[cfg(not(feature = "zeroize"))]
pub struct ExportableArrayInner<const N: usize>(pub [u8; N]);

/// Debug implementation (always redacted).
impl<const N: usize> core::fmt::Debug for ExportableArrayInner<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Marker impl for serialization of raw byte arrays.
impl<const N: usize> crate::SerializableSecret for ExportableArrayInner<N> {}

/// Serde serialization support for raw byte arrays.
#[cfg(feature = "serde-serialize")]
impl<const N: usize> serde::Serialize for ExportableArrayInner<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Secure encoding support for the inner array bytes.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<const N: usize> crate::SecureEncoding for ExportableArrayInner<N> {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> crate::HexString {
        self.0.to_hex()
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        self.0.to_hex_upper()
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> crate::Base64String {
        self.0.to_base64url()
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> core::result::Result<crate::Bech32String, crate::Bech32EncodingError> {
        self.0.try_to_bech32(hrp)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> core::result::Result<crate::Bech32String, crate::Bech32EncodingError> {
        self.0.try_to_bech32m(hrp)
    }
}

/// A fixed-size byte array wrapped as an exportable secret for raw serialization.
///
/// This type provides a secure wrapper around a `[u8; N]` that enables opt-in
/// serialization of raw bytes. Use this for sensitive fixed-size data like keys
/// that need to be deliberately exported.
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
/// use secure_gate::ExportableArray;
/// let key: ExportableArray<32> = [42u8; 32].into();
/// // key now enables serialization
/// # }
/// ```
pub type ExportableArray<const N: usize> = crate::Fixed<ExportableArrayInner<N>>;

impl<const N: usize> ExportableArray<N> {
    /// Construct an exportable array secret from a byte array.
    ///
    /// This wraps the array in a secure container for potential serialization.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::Fixed;
    /// use secure_gate::exportable::ExportableArrayInner;
    /// let secret: secure_gate::ExportableArray<4> = Fixed::new(ExportableArrayInner([1, 2, 3, 4]));
    /// # }
    /// ```

    /// Build an exportable array secret in a closure.
    ///
    /// This minimizes stack exposure by building the array temporarily.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "serde-serialize")]
    /// # {
    /// use secure_gate::Fixed;
    /// use secure_gate::exportable::ExportableArrayInner;
    /// let secret = Fixed::new(ExportableArrayInner([1, 2, 3, 4])); // from init_with equiv
    /// # }
    /// ```
    #[inline(always)]
    pub fn init_with<F>(constructor: F) -> Self
    where
        F: FnOnce() -> [u8; N],
    {
        let mut tmp = constructor();
        let result = crate::Fixed::new(ExportableArrayInner(tmp));
        #[cfg(feature = "zeroize")]
        ::zeroize::Zeroize::zeroize(&mut tmp);
        result
    }
}

#[cfg(feature = "serde-serialize")]
impl<const N: usize> core::convert::From<crate::Fixed<[u8; N]>> for ExportableArray<N> {
    fn from(value: crate::Fixed<[u8; N]>) -> Self {
        let array = *value.expose_secret();
        crate::Fixed::new(ExportableArrayInner(array))
    }
}

impl<const N: usize> core::convert::From<[u8; N]> for ExportableArray<N> {
    fn from(value: [u8; N]) -> Self {
        crate::Fixed::new(ExportableArrayInner(value))
    }
}

impl<const N: usize> core::convert::TryFrom<&[u8]> for ExportableArray<N> {
    type Error = crate::FromSliceError;

    fn try_from(value: &[u8]) -> core::result::Result<Self, Self::Error> {
        if value.len() == N {
            let mut array = [0u8; N];
            array.copy_from_slice(value);
            Ok(crate::Fixed::new(ExportableArrayInner(array)))
        } else {
            Err(crate::FromSliceError {
                actual_len: value.len(),
                expected_len: N,
            })
        }
    }
}

/// Secure encoding support for the exportable array.
#[cfg(any(
    feature = "encoding-hex",
    feature = "encoding-base64",
    feature = "encoding-bech32"
))]
impl<const N: usize> crate::SecureEncoding for ExportableArray<N> {
    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex(&self) -> crate::HexString {
        self.0.to_hex()
    }

    #[cfg(feature = "encoding-hex")]
    #[inline(always)]
    fn to_hex_upper(&self) -> alloc::string::String {
        self.0.to_hex_upper()
    }

    #[cfg(feature = "encoding-base64")]
    #[inline(always)]
    fn to_base64url(&self) -> crate::Base64String {
        self.0.to_base64url()
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32(
        &self,
        hrp: &str,
    ) -> core::result::Result<crate::Bech32String, crate::Bech32EncodingError> {
        self.0.try_to_bech32(hrp)
    }

    #[cfg(feature = "encoding-bech32")]
    #[inline(always)]
    fn try_to_bech32m(
        &self,
        hrp: &str,
    ) -> core::result::Result<crate::Bech32String, crate::Bech32EncodingError> {
        self.0.try_to_bech32m(hrp)
    }
}

#[cfg(feature = "serde-serialize")]
impl<const N: usize> core::convert::From<crate::CloneableArray<N>> for ExportableArray<N> {
    fn from(value: crate::CloneableArray<N>) -> Self {
        let inner = value.expose_secret();
        let array = inner.0;
        crate::Fixed::new(ExportableArrayInner(array))
    }
}
