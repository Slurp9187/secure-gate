// Creates a cloneable type alias for a fixed-size secure secret.
///
/// This macro generates a newtype around `Fixed<[u8; N]>` with implementations for `Clone` and `CloneableType`.
/// It inherits the security properties of `Fixed` but allows explicit duplication via `Clone`.
///
/// # Syntax
///
/// `cloneable_fixed_alias!(vis Name, size);` — visibility required (e.g., `pub`)
#[macro_export]
macro_rules! cloneable_fixed_alias {
    ($vis:vis $name:ident, $size:literal) => {
        #[doc = concat!("Cloneable fixed-size secure secret (", stringify!($size), " bytes)")]
        $vis struct $name($crate::Fixed<[u8; $size]>);

        #[cfg(feature = "cloneable")]
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self($crate::Fixed::new((*self.0.expose_secret()).clone()))
            }
        }

        #[cfg(feature = "cloneable")]
        impl $crate::CloneableType for $name {}

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

        impl $crate::ExposeSecretMut for $name {
            fn expose_secret_mut(&mut self) -> &mut Self::Inner {
                self.0.expose_secret_mut()
            }
        }

        #[cfg(feature = "ct-eq")]
        impl $crate::ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> bool {
                self.expose_secret().ct_eq(other.expose_secret())
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
                self.expose_secret().to_hex()
            }

            #[cfg(feature = "encoding-hex")]
            fn to_hex_upper(&self) -> alloc::string::String {
                self.expose_secret().to_hex_upper()
            }

            #[cfg(feature = "encoding-base64")]
            fn to_base64url(&self) -> alloc::string::String {
                self.expose_secret().to_base64url()
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32(&self, hrp: &str) -> alloc::string::String {
                self.expose_secret().to_bech32(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn to_bech32m(&self, hrp: &str) -> alloc::string::String {
                self.expose_secret().to_bech32m(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn try_to_bech32(&self, hrp: &str) -> Result<alloc::string::String, $crate::Bech32EncodingError> {
                self.expose_secret().try_to_bech32(hrp)
            }

            #[cfg(feature = "encoding-bech32")]
            fn try_to_bech32m(&self, hrp: &str) -> Result<alloc::string::String, $crate::Bech32EncodingError> {
                self.expose_secret().try_to_bech32m(hrp)
            }
        }

        impl std::ops::Deref for $name {
            type Target = $crate::Fixed<[u8; $size]>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl $name {
            /// Initialize with a closure that returns the secret data.
            pub fn init_with<F>(f: F) -> Self
            where
                F: FnOnce() -> [u8; $size],
            {
                Self($crate::Fixed::new(f()))
            }

            /// Try to initialize with a closure that may fail.
            pub fn try_init_with<F, E>(f: F) -> Result<Self, E>
            where
                F: FnOnce() -> Result<[u8; $size], E>,
            {
                f().map(|arr| Self($crate::Fixed::new(arr)))
            }
        }
    };
}
