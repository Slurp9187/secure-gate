//! `dynamic_newtype!` — nominal newtype over `Dynamic<T>`.
//!
//! **UNMERGED SPIKE — targets 0.10, not 0.9.0.** One design decision is
//! unresolved; see `docs/nominal_newtypes.md` §5.1 before merging.

/// Creates a distinct nominal type wrapping [`Dynamic<T>`](crate::Dynamic).
///
/// Mirrors [`dynamic_alias!`](crate::dynamic_alias) syntax. `String` and `Vec<u8>`
/// (written exactly so) get the full byte/string API; any other `T` gets the
/// shared trait surface plus `new`.
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! dynamic_newtype {
    ($(#[$attr:meta])* $vis:vis $name:ident, $inner:ty, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, $inner);
    };

    // ---- String arm: matched by literal tokens, before the generic arm ----
    ($(#[$attr:meta])* $vis:vis $name:ident, String) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Dynamic<$crate::__private::String>));
        $crate::__sg_dynamic_ctor!($name, $crate::__private::String);

        impl ::core::convert::From<&str> for $name {
            #[inline]
            fn from(s: &str) -> Self { Self(<$crate::Dynamic<$crate::__private::String>>::from(s)) }
        }
        impl $name {
            /// Scoped construction into a protected `String` buffer.
            #[inline]
            pub fn new_with<F>(f: F) -> Self
            where F: ::core::ops::FnOnce(&mut $crate::__private::String) {
                Self(<$crate::Dynamic<$crate::__private::String>>::new_with(f))
            }
        }
    };

    // ---- Vec<u8> arm ----
    ($(#[$attr:meta])* $vis:vis $name:ident, Vec<u8>) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Dynamic<$crate::__private::Vec<u8>>));
        $crate::__sg_dynamic_ctor!($name, $crate::__private::Vec<u8>);

        impl ::core::convert::From<&[u8]> for $name {
            #[inline]
            fn from(s: &[u8]) -> Self { Self(<$crate::Dynamic<$crate::__private::Vec<u8>>>::from(s)) }
        }
        impl $name {
            /// Scoped construction into a protected `Vec<u8>` buffer.
            #[inline]
            pub fn new_with<F>(f: F) -> Self
            where F: ::core::ops::FnOnce(&mut $crate::__private::Vec<u8>) {
                Self(<$crate::Dynamic<$crate::__private::Vec<u8>>>::new_with(f))
            }
        }

        $crate::__sg_if_rand! {
            impl $name {
                /// Generates `len` random bytes from the system RNG.
                #[inline]
                pub fn from_random(len: usize) -> Self { Self(<$crate::Dynamic<$crate::__private::Vec<u8>>>::from_random(len)) }
            }
        }

        $crate::__sg_if_hex! {
            impl $name {
                /// Constant-time hex decode into this secret type.
                #[inline]
                pub fn try_from_hex(s: &str) -> ::core::result::Result<Self, $crate::HexError> {
                    ::core::result::Result::Ok(Self(<$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_hex(s)?))
                }
                /// Encodes as lowercase hex.
                #[inline]
                pub fn to_hex(&self) -> $crate::__private::String { self.0.to_hex() }
                /// Encodes as lowercase hex into a zeroizing wrapper.
                #[inline]
                pub fn to_hex_zeroizing(&self) -> $crate::EncodedSecret { self.0.to_hex_zeroizing() }
            }
        }

        $crate::__sg_if_std! {
            impl ::std::io::Write for $name {
                #[inline]
                fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                    ::std::io::Write::write(&mut self.0, buf)
                }
                #[inline]
                fn flush(&mut self) -> ::std::io::Result<()> { ::std::io::Write::flush(&mut self.0) }
            }
            impl $name {
                /// Zeroizing reader over the secret bytes.
                #[inline]
                pub fn as_reader(&self) -> $crate::DynamicReader<'_> { self.0.as_reader() }
            }
        }
    };

    // ---- generic arm: any other T ----
    ($(#[$attr:meta])* $vis:vis $name:ident, $inner:ty) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Dynamic<$inner>));
        $crate::__sg_dynamic_ctor!($name, $inner);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __sg_dynamic_ctor {
    ($name:ident, $inner:ty) => {
        impl $name {
            /// Moves a value onto the heap as this secret type.
            #[inline(always)]
            pub fn new<U>(value: U) -> Self
            where
                U: ::core::convert::Into<$crate::__private::Box<$inner>>,
            {
                Self(<$crate::Dynamic<$inner>>::new(value))
            }
        }
    };
}
