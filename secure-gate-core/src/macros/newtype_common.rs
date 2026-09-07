//! Shared machinery for `fixed_newtype!` / `dynamic_newtype!`.
//!
//! Ships in 0.9.0. Design record: `docs/nominal_newtypes.md`.

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



        impl ::core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str("[REDACTED]")
            }
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
    // `Clone` and `Serialize` are deliberately NOT offered here.
    //
    // Forwarding the wrapper's impls is impossible: `Fixed<[u8; N]>: Clone`
    // requires `[u8; N]: CloneableSecret`, which the orphan rule makes
    // permanently unimplementable downstream (deliberately — see
    // `traits/cloneable_secret.rs`). The only mechanism available to a
    // generated impl is to route through `with_secret` and rebuild, which
    // opts the secret into cloning/serialization with no marker impl
    // anywhere — a second door around the opt-in system, spelled in one word
    // inside a macro expansion.
    //
    // A generated newtype is local to the caller's crate, so a caller who
    // genuinely wants this can write the impl by hand, where the decision is
    // visible and greppable in their own code. That is the intended path;
    // see the `Clone` example on `fixed_newtype!`.
    (Clone, $name:ident, $wrapper:ty) => {
        ::core::compile_error!(
            "secure_newtype: `derive: [Clone]` is not supported. Cloning a secret \
             cannot be forwarded (the wrapper's `Clone` needs `CloneableSecret` on \
             the inner type, which downstream crates cannot implement), so a \
             generated impl would have to route around the opt-in marker system. \
             Write `impl Clone for YourType` by hand if you mean it — the newtype \
             is local to your crate, so the decision stays visible in your code."
        );
    };
    (Serialize, $name:ident, $wrapper:ty) => {
        ::core::compile_error!(
            "secure_newtype: `derive: [Serialize]` is not supported. Serializing a \
             secret cannot be forwarded (the wrapper's `Serialize` needs \
             `SerializableSecret` on the inner type, which downstream crates cannot \
             implement), so a generated impl would have to route around the opt-in \
             marker system. Write `impl Serialize for YourType` by hand if you mean \
             it — serialization exposes the full secret, so make it a visible, \
             audited decision in your own code."
        );
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
    // Base-wrapper access is opt-in (R2 of the downstream requirements) and
    // split by direction, because the two directions carry different risk.
    //
    //   FromWrapper — INBOUND: `from_wrapper(base) -> Self`. A base-typed value
    //                 becomes this role. Every plain alias of the same base is
    //                 already that base type, so this is the relabelling path;
    //                 a type that guards a boundary should never take it.
    //   IntoWrapper — OUTBOUND: `as_wrapper`, `as_wrapper_mut`, `into_wrapper`.
    //                 Material leaves this role toward the base type. Needed to
    //                 reach base API that is not forwarded. In a mixed tree the
    //                 base type is every plain alias too, so on a secret role
    //                 this is a downgrade to the pool's least-sensitive alias.
    //   WrapperAccess — shorthand for both. Do not combine it with either
    //                 directional token (duplicate method definitions).
    //
    // With none of these, the only way material enters or leaves a newtype is
    // the 3-tier access API — a `with_secret` round trip. No `From<Wrapper>` is
    // ever generated.
    (FromWrapper, $name:ident, $wrapper:ty) => {
        impl $name {
            /// Wraps an existing secure wrapper in this nominal type.
            #[inline(always)]
            pub fn from_wrapper(wrapper: $wrapper) -> Self {
                Self(wrapper)
            }
        }
    };
    (IntoWrapper, $name:ident, $wrapper:ty) => {
        impl $name {
            /// Borrows the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn as_wrapper(&self) -> &$wrapper {
                &self.0
            }
            /// Mutably borrows the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn as_wrapper_mut(&mut self) -> &mut $wrapper {
                &mut self.0
            }
            /// Unwraps to the underlying wrapper (drops nominal separation).
            #[inline(always)]
            pub fn into_wrapper(self) -> $wrapper {
                self.0
            }
        }
    };
    (WrapperAccess, $name:ident, $wrapper:ty) => {
        $crate::__sg_newtype_opt!(FromWrapper, $name, $wrapper);
        $crate::__sg_newtype_opt!(IntoWrapper, $name, $wrapper);
    };
    ($other:ident, $name:ident, $wrapper:ty) => {
        ::core::compile_error!(::core::concat!(
            "secure_newtype: unknown `derive:` option `",
            ::core::stringify!($other),
            "`. Supported: ConstantTimeEq, Deserialize, FromWrapper, IntoWrapper, WrapperAccess. `Clone` and \
             `Serialize` are deliberately unsupported — write them by hand."
        ));
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

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encoding-base32")]
macro_rules! __sg_if_base32 { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encoding-base32"))]
macro_rules! __sg_if_base32 {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encoding-base64")]
macro_rules! __sg_if_base64 { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encoding-base64"))]
macro_rules! __sg_if_base64 {
    ($($t:tt)*) => {};
}

#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encoding-bech32m")]
macro_rules! __sg_if_bech32m { ($($t:tt)*) => { $($t)* }; }
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encoding-bech32m"))]
macro_rules! __sg_if_bech32m {
    ($($t:tt)*) => {};
}
