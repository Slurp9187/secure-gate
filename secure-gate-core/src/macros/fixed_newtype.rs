//! `fixed_newtype!` — nominal newtype over `Fixed<[u8; N]>`.
//!
//! **UNMERGED SPIKE — targets 0.10, not 0.9.0.** One design decision is
//! unresolved; see `docs/nominal_newtypes.md` §5.1 before merging.

/// Creates a distinct nominal type wrapping [`Fixed<[u8; N]>`](crate::Fixed).
///
/// Mirrors [`fixed_alias!`](crate::fixed_alias) syntax, but generates a `struct`
/// rather than a `type` alias: two `fixed_newtype!` types of the same `N` are
/// **not** interchangeable.
#[macro_export]
macro_rules! fixed_newtype {
    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal, $doc:literal) => {
        $crate::fixed_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $size);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, $size:literal) => {
        const _: () = { let _ = [(); $size][0]; };

        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Fixed<[u8; $size]>));
        $crate::__sg_newtype_len!($name);

        impl $name {
            /// Wraps a fixed-size byte array. `const fn`, like `Fixed::new`.
            #[inline(always)]
            pub const fn new(value: [u8; $size]) -> Self {
                Self($crate::Fixed::new(value))
            }
            /// Scoped construction — writes directly into the wrapper's storage.
            #[inline(always)]
            pub fn new_with<F>(f: F) -> Self
            where F: ::core::ops::FnOnce(&mut [u8; $size]) {
                Self($crate::Fixed::new_with(f))
            }
        }

        impl ::core::convert::From<[u8; $size]> for $name {
            #[inline(always)]
            fn from(value: [u8; $size]) -> Self { Self($crate::Fixed::new(value)) }
        }

        impl ::core::convert::TryFrom<&[u8]> for $name {
            type Error = $crate::FromSliceError;
            #[inline]
            fn try_from(slice: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                ::core::result::Result::Ok(Self(
                    <$crate::Fixed<[u8; $size]> as ::core::convert::TryFrom<&[u8]>>::try_from(slice)?
                ))
            }
        }

        $crate::__sg_if_rand! {
            impl $name {
                /// Generates the secret from the system RNG.
                #[inline]
                pub fn from_random() -> Self { Self($crate::Fixed::from_random()) }
            }
        }

        $crate::__sg_if_hex! {
            impl $name {
                /// Constant-time hex decode into this secret type.
                #[inline]
                pub fn try_from_hex(hex: &str) -> ::core::result::Result<Self, $crate::HexError> {
                    ::core::result::Result::Ok(Self($crate::Fixed::try_from_hex(hex)?))
                }
            }
            $crate::__sg_if_alloc! {
                impl $crate::ToHex for $name {
                    #[inline]
                    fn to_hex(&self) -> $crate::__private::String {
                        $crate::ToHex::to_hex(&self.0)
                    }
                    #[inline]
                    fn to_hex_upper(&self) -> $crate::__private::String {
                        $crate::ToHex::to_hex_upper(&self.0)
                    }
                    #[inline]
                    fn to_hex_zeroizing(&self) -> $crate::EncodedSecret {
                        $crate::ToHex::to_hex_zeroizing(&self.0)
                    }
                    #[inline]
                    fn to_hex_upper_zeroizing(&self) -> $crate::EncodedSecret {
                        $crate::ToHex::to_hex_upper_zeroizing(&self.0)
                    }
                }
            }
        }

        $crate::__sg_if_bech32! {
            $crate::__sg_if_alloc! {
                impl $crate::ToBech32 for $name {
                    #[inline]
                    fn try_to_bech32(
                        &self,
                        hrp: &str,
                    ) -> ::core::result::Result<$crate::__private::String, $crate::Bech32Error> {
                        $crate::ToBech32::try_to_bech32(&self.0, hrp)
                    }
                    #[inline]
                    fn try_to_bech32_zeroizing(
                        &self,
                        hrp: &str,
                    ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                        $crate::ToBech32::try_to_bech32_zeroizing(&self.0, hrp)
                    }
                }
                impl $name {
                    /// HRP-validated Bech32 decode into this secret type.
                    #[inline]
                    pub fn try_from_bech32(s: &str, expected_hrp: &str)
                        -> ::core::result::Result<Self, $crate::Bech32Error> {
                        ::core::result::Result::Ok(Self($crate::Fixed::try_from_bech32(s, expected_hrp)?))
                    }
                }
            }
        }
    };
}
