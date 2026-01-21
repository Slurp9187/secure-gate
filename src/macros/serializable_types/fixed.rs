// Creates a serializable type alias for a fixed-size secure secret.
//
// This macro generates a newtype around `Fixed<[u8; N]>` with implementations for `Serialize` and `SerializableType`.
// It inherits the security properties of `Fixed` but allows deliberate serialization via `Serialize`.
//
// # Syntax
//
// `serializable_fixed_alias!(vis Name, size);` — visibility required (e.g., `pub`)
#[macro_export]
macro_rules! serializable_fixed_alias {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Serializable fixed-size secure secret (", stringify!($size), " bytes)")]
        $vis struct $name($crate::Fixed<[u8; $size]>);

        #[cfg(feature = "serde")]
        impl $crate::SerializableType for $name {}

        impl $crate::ExposeSecret for $name {
            type Inner = [u8; $size];

            #[inline(always)]
            fn expose_secret(&self) -> &[u8; $size] {
                self.0.expose_secret()
            }

            #[inline(always)]
            fn len(&self) -> usize {
                $size
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
                <$name as $crate::ExposeSecret>::expose_secret(self).to_hex()
            }

            #[cfg(feature = "encoding-hex")]
            fn to_hex_upper(&self) -> alloc::string::String {
                <$name as $crate::ExposeSecret>::expose_secret(self).to_hex_upper()
            }

            #[cfg(feature = "encoding-base64")]
            fn to_base64url(&self) -> alloc::string::String {
                <$name as $crate::ExposeSecret>::expose_secret(self).to_base64url()
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32(&self, hrp: &str) -> alloc::string::String {
                <$name as $crate::ExposeSecret>::expose_secret(self).to_bech32(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
                <$name as $crate::ExposeSecret>::expose_secret(self).to_bech32m(hrp)
            }
        }

        #[cfg(feature = "ct-eq")]
        impl $crate::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> bool {
                <$name as $crate::ExposeSecret>::expose_secret(self).ct_eq(<$name as $crate::ExposeSecret>::expose_secret(other))
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(arr: [u8; $size]) -> Self {
                Self($crate::Fixed::new(arr))
            }
        }

        impl From<&[u8]> for $name {
            fn from(slice: &[u8]) -> Self {
                Self($crate::Fixed::from(slice))
            }
        }

        impl std::ops::Deref for $name {
            type Target = $crate::Fixed<[u8; $size]>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        // Assuming serde feature is enabled
        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                <$crate::Fixed<[u8; $size]> as $crate::ExposeSecret>::expose_secret(&self.0).serialize(serializer)
            }
        }

        #[cfg(all(feature = "serde-deserialize", feature = "serde-serialize"))]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let inner = <[u8; $size]>::deserialize(deserializer)?;
                Ok(Self::from(inner))
            }
        }
    };
}
