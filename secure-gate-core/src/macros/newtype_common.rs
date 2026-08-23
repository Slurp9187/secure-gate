//! Shared machinery for `fixed_newtype!` / `dynamic_newtype!`.
//!
//! **UNMERGED SPIKE — targets 0.10, not 0.9.0.** One design decision is
//! unresolved; see `docs/nominal_newtypes.md` §5.1 before merging.

// ---- cfg relays -------------------------------------------------------------
// `#[cfg(feature = "...")]` inside an exported macro is evaluated in the CALLER's
// crate, against the CALLER's features. These relays capture secure-gate's own
// feature state at definition time and are called as `$crate::__sg_if_*!{ ... }`.

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "ct-eq")]
macro_rules! __sg_if_ct_eq { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "ct-eq"))]
macro_rules! __sg_if_ct_eq {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "cloneable")]
macro_rules! __sg_if_cloneable { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "cloneable"))]
macro_rules! __sg_if_cloneable {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "serde-serialize")]
macro_rules! __sg_if_ser { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "serde-serialize"))]
macro_rules! __sg_if_ser {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "serde-deserialize")]
macro_rules! __sg_if_de { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "serde-deserialize"))]
macro_rules! __sg_if_de {
    ($($t:tt)*) => {};
}

/// Internal: struct + trait surface shared by both front-end macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __sg_newtype_base {
    ($(#[$attr:meta])* $vis:vis $name:ident($wrapper:ty)) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($wrapper), derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident($wrapper:ty), derive: [$($opt:ident),* $(,)?]) => {
        $(#[$attr])*
        #[repr(transparent)]
        #[must_use = "holds secret material; bind it or chain a method call"]
        $vis struct $name($wrapper);


        impl $name {
            /// Wraps an existing secure wrapper in this nominal type.
            #[inline(always)]
            pub fn from_wrapper(wrapper: $wrapper) -> Self { Self(wrapper) }
            /// Borrows the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn as_wrapper(&self) -> &$wrapper { &self.0 }
            /// Mutably borrows the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn as_wrapper_mut(&mut self) -> &mut $wrapper { &mut self.0 }
            /// Unwraps to the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn into_wrapper(self) -> $wrapper { self.0 }
        }

        impl ::core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str("[REDACTED]")
            }
        }

        impl ::core::convert::From<$wrapper> for $name {
            #[inline(always)]
            fn from(wrapper: $wrapper) -> Self { Self(wrapper) }
        }

        impl $crate::RevealSecret for $name {
            type Inner = <$wrapper as $crate::RevealSecret>::Inner;

            #[inline(always)]
            fn with_secret<F, R>(&self, f: F) -> R
            where F: ::core::ops::FnOnce(&Self::Inner) -> R {
                $crate::RevealSecret::with_secret(&self.0, f)
            }
            #[inline(always)]
            fn expose_secret(&self) -> &Self::Inner {
                $crate::RevealSecret::expose_secret(&self.0)
            }
            #[inline(always)]
            fn into_inner(self) -> $crate::InnerSecret<Self::Inner>
            where
                Self: Sized,
                Self::Inner: Sized + $crate::SentinelValue + $crate::__private::Zeroize,
            {
                $crate::RevealSecret::into_inner(self.0)
            }
        }

        impl $crate::RevealSecretMut for $name {
            #[inline(always)]
            fn with_secret_mut<F, R>(&mut self, f: F) -> R
            where F: ::core::ops::FnOnce(&mut Self::Inner) -> R {
                $crate::RevealSecretMut::with_secret_mut(&mut self.0, f)
            }
            #[inline(always)]
            fn expose_secret_mut(&mut self) -> &mut Self::Inner {
                $crate::RevealSecretMut::expose_secret_mut(&mut self.0)
            }
        }

        impl $crate::__private::Zeroize for $name {
            #[inline(always)]
            fn zeroize(&mut self) { $crate::__private::Zeroize::zeroize(&mut self.0) }
        }
        impl $crate::__private::ZeroizeOnDrop for $name {}

        $(
            $crate::__sg_newtype_opt!($opt, $name, $wrapper);
        )*
    };
}

/// Opt-in impls, selected by name in the `derive:` list.
#[doc(hidden)]
#[macro_export]
macro_rules! __sg_newtype_opt {
    (ConstantTimeEq, $name:ident, $wrapper:ty) => {
        $crate::__sg_if_ct_eq! {
            impl $crate::ConstantTimeEq for $name {
                #[inline]
                fn ct_eq(&self, other: &Self) -> bool {
                    $crate::ConstantTimeEq::ct_eq(&self.0, &other.0)
                }
            }
        }
    };
    (Clone, $name:ident, $wrapper:ty) => {
        $crate::__sg_if_cloneable! {
            impl ::core::clone::Clone for $name {
                #[inline]
                fn clone(&self) -> Self {
                    Self($crate::RevealSecret::with_secret(&self.0, |inner| {
                        ::core::convert::From::from(::core::clone::Clone::clone(inner))
                    }))
                }
            }
        }
    };
    (Serialize, $name:ident, $wrapper:ty) => {
        $crate::__sg_if_ser! {
            impl $crate::__private::Serialize for $name {
                #[inline]
                fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
                where S: $crate::__private::Serializer {
                    $crate::RevealSecret::with_secret(&self.0, |inner| {
                        $crate::__private::Serialize::serialize(inner, serializer)
                    })
                }
            }
        }
    };
    (Deserialize, $name:ident, $wrapper:ty) => {
        $crate::__sg_if_de! {
            impl<'de> $crate::__private::Deserialize<'de> for $name {
                #[inline]
                fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
                where D: $crate::__private::Deserializer<'de> {
                    ::core::result::Result::Ok(Self(
                        $crate::__private::Deserialize::deserialize(deserializer)?,
                    ))
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "rand")]
macro_rules! __sg_if_rand { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "rand"))]
macro_rules! __sg_if_rand {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "alloc")]
macro_rules! __sg_if_alloc { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "alloc"))]
macro_rules! __sg_if_alloc {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "std")]
macro_rules! __sg_if_std { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "std"))]
macro_rules! __sg_if_std {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encoding-hex")]
macro_rules! __sg_if_hex { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encoding-hex"))]
macro_rules! __sg_if_hex {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encoding-bech32")]
macro_rules! __sg_if_bech32 { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encoding-bech32"))]
macro_rules! __sg_if_bech32 {
    ($($t:tt)*) => {};
}

/// Internal: forwards [`SecretLen`](crate::SecretLen) to the wrapped field.
/// Emitted by the front-end macros whose wrapper shape has a meaningful length
/// (`Fixed<[u8; N]>`, `Dynamic<String>`, `Dynamic<Vec<u8>>`); the generic
/// `dynamic_newtype!` arm deliberately does not emit it.
#[doc(hidden)]
#[macro_export]
macro_rules! __sg_newtype_len {
    ($name:ident) => {
        impl $crate::SecretLen for $name {
            #[inline(always)]
            fn len(&self) -> usize {
                $crate::SecretLen::len(&self.0)
            }
            #[inline(always)]
            fn byte_len(&self) -> usize {
                $crate::SecretLen::byte_len(&self.0)
            }
        }
    };
}
