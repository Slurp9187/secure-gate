
/// Creates a serializable type alias for a dynamic heap-allocated secure secret.
///
/// This macro generates a newtype around `Dynamic<T>` with implementations for `Serialize` and `SerializableType`.
/// It inherits the security properties of `Dynamic` but allows deliberate serialization via `Serialize`.
///
/// # Syntax
///
/// `serializable_dynamic_alias!(vis Name, Type);` — visibility required (e.g., `pub`), Type is the inner type like `String` or `Vec<u8>`
///
/// **Security Warning**
/// This macro creates a deliberately serializable type.
/// Serialization can lead to accidental secret leakage via:
/// - debug printing / logging
/// - insecure configuration files
/// - network payloads without encryption
/// - debug endpoints or introspection tools
///
/// Only use this macro when serialization is explicitly required (e.g., persisting to trusted encrypted storage, sending over authenticated secure channels).
///
/// **Prefer non-serializable `Fixed<T>` / `Dynamic<T>` whenever possible** to eliminate the risk of exfiltration entirely.

#[macro_export]
macro_rules! serializable_dynamic_alias {
    ($vis:vis $name:ident, $type:ty) => {
        #[doc = concat!("Serializable dynamic secure secret (", stringify!($type), ")")]
        $vis struct $name($crate::Dynamic<$type>);

        #[cfg(feature = "serde")]
        impl $crate::SerializableType for $name {}

        impl $crate::ExposeSecret for $name {
            type Inner = $type;

            #[inline(always)]
            fn expose_secret(&self) -> &$type {
                self.0.expose_secret()
            }

            #[inline(always)]
            fn len(&self) -> usize {
                self.0.len()
            }
        }

        impl $crate::ExposeSecretMut for $name {
            fn expose_secret_mut(&mut self) -> &mut Self::Inner {
                self.0.expose_secret_mut()
            }
        }

        #[cfg(any(
            feature = "encoding-hex",
            feature = "encoding-base64",
            feature = "encoding-bech32"
        ))]
        impl $crate::SecureEncoding for $name {
            #[cfg(feature = "encoding-hex")]
            fn to_hex(&self) -> alloc::string::String {
                $crate::ExposeSecret::expose_secret(self).to_hex()
            }

            #[cfg(feature = "encoding-hex")]
            fn to_hex_upper(&self) -> alloc::string::String {
                $crate::ExposeSecret::expose_secret(self).to_hex_upper()
            }

            #[cfg(feature = "encoding-base64")]
            fn to_base64url(&self) -> alloc::string::String {
                $crate::ExposeSecret::expose_secret(self).to_base64url()
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32(&self, hrp: &str) -> alloc::string::String {
                $crate::ExposeSecret::expose_secret(self).to_bech32(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
                $crate::ExposeSecret::expose_secret(self).to_bech32m(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn try_to_bech32(&self, hrp: &str) -> Result<alloc::string::String, $crate::Bech32EncodingError> {
                $crate::ExposeSecret::expose_secret(self).try_to_bech32(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, $crate::Bech32EncodingError> {
                $crate::ExposeSecret::expose_secret(self).try_to_bech32m(hrp)
            }
        }

        #[cfg(feature = "ct-eq")]
        impl $crate::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> bool {
                $crate::ExposeSecret::expose_secret(self).ct_eq($crate::ExposeSecret::expose_secret(other))
            }
        }

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self($crate::Dynamic::new(value))
            }
        }

        impl std::ops::Deref for $name {
            type Target = $crate::Dynamic<$type>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        // Assuming serde feature is enabled
        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.expose_secret().serialize(serializer)
            }
        }

        #[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
        impl<'de> serde::Deserialize<'de> for $name
        where
            $type: serde::de::DeserializeOwned,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = <$type>::deserialize(deserializer)?;
                Ok(Self::from(inner))
            }
        }
    };
}
