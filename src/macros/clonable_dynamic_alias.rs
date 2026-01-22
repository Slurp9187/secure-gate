// Creates a cloneable type alias for a dynamic heap-allocated secure secret.
///
/// This macro generates a newtype around `Dynamic<T>` with implementations for `Clone` and `CloneableType`.
/// It inherits the security properties of `Dynamic` but allows explicit duplication via `Clone`.
///
/// # Syntax
///
/// `cloneable_dynamic_alias!(vis Name, Type);` — visibility required (e.g., `pub`), Type is the inner type like `String` or `Vec<u8>`
#[macro_export]
macro_rules! cloneable_dynamic_alias {
    ($vis:vis $name:ident, $type:ty) => {
        #[doc = concat!("Cloneable dynamic secure secret (", stringify!($type), ")")]
        $vis struct $name($crate::Dynamic<$type>);

        #[cfg(feature = "cloneable")]
        impl Clone for $name {
            fn clone(&self) -> Self {
                Self($crate::Dynamic::new((*self.0.expose_secret()).clone()))
            }
        }

        #[cfg(feature = "cloneable")]
        impl $crate::CloneableType for $name {}

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
            type Target = $crate::Dynamic<$type>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<$type> for $name {
            fn from(value: $type) -> Self {
                Self($crate::Dynamic::new(value))
            }
        }

        impl $name {
            /// Initialize with a closure that returns the secret data.
            pub fn init_with<F>(f: F) -> Self
            where
                F: FnOnce() -> $type,
            {
                Self($crate::Dynamic::new(f()))
            }

            /// Try to initialize with a closure that may fail.
            pub fn try_init_with<F, E>(f: F) -> Result<Self, E>
            where
                F: FnOnce() -> Result<$type, E>,
            {
                f().map(|value| Self($crate::Dynamic::new(value)))
            }
        }
    };
}
