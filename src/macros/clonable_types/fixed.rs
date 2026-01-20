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

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self($crate::Fixed::new(self.0.expose_secret().clone()))
            }
        }

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
    };
}
