//! `dynamic_newtype!` — nominal newtype over `Dynamic<T>`.
//!
//! **UNMERGED SPIKE — targets 0.10, not 0.9.0.** See
//! `docs/nominal_newtypes.md` for the design record and remaining work (§6
//! polish) before merging.

/// Creates a distinct nominal type wrapping [`Dynamic<T>`](crate::Dynamic).
///
/// Mirrors [`dynamic_alias!`](crate::dynamic_alias) syntax, but generates a
/// `struct` rather than a `type` alias: two `dynamic_newtype!` types over the
/// same inner type are **not** interchangeable.
///
/// # Inner types must be written literally
///
/// Macros match **tokens**, not resolved types. `String` and `Vec<u8>` are
/// matched as literal tokens, so they must be spelled exactly that way to get
/// the full API for their shape:
///
/// ```rust
/// # #[cfg(feature = "alloc")] {
/// use secure_gate::{dynamic_newtype, SecretLen};
///
/// dynamic_newtype!(pub ApiKey, String);       // full String API
/// dynamic_newtype!(pub Token, Vec<u8>);       // full byte API: hex, io::Write, …
///
/// let k: ApiKey = "sk_live".into();
/// assert_eq!(k.len(), 7);
/// # }
/// ```
///
/// A type alias (`type MyStr = String`) or a fully-qualified path
/// (`std::string::String`) is a *different token sequence*, so it cannot reach
/// those arms — and no macro can see through it, because macro expansion runs
/// before type resolution. Rather than silently hand back a newtype missing
/// half its API, such input is a **compile error** naming the fix.
///
/// When the inner type genuinely is something else, opt in with `generic`:
///
/// ```rust
/// # #[cfg(feature = "alloc")] {
/// use secure_gate::{dynamic_newtype, RevealSecret};
///
/// dynamic_newtype!(pub Counters, generic Vec<u32>);
///
/// let c = Counters::new(vec![1u32, 2, 3]);
/// assert_eq!(c.with_secret(|v| v.len()), 3);
/// # }
/// ```
///
/// The `generic` form deliberately provides less: [`RevealSecret`](crate::RevealSecret),
/// [`RevealSecretMut`](crate::RevealSecretMut), redacted `Debug`, `Zeroize`,
/// `ZeroizeOnDrop`, and `new` — no [`SecretLen`](crate::SecretLen) and no
/// encoders, since neither is meaningful for an arbitrary inner type. Writing
/// the marker is how you say you know that.
#[cfg(feature = "alloc")]
#[macro_export]
macro_rules! dynamic_newtype {
    // ---- doc-string forms, one per shape ----
    //
    // These must be matched by literal tokens *before* any arm that opens with
    // a `$inner:ty` fragment. `macro_rules!` does not backtrack once a `:ty`
    // fragment has been parsed: a single `$inner:ty, $doc:literal` arm would
    // consume the type, fail to find the comma, and hard-error with "unexpected
    // end of macro invocation" instead of falling through to the arms below.
    ($(#[$attr:meta])* $vis:vis $name:ident, String, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, String);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, Vec<u8>, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, Vec<u8>);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, generic $inner);
    };

    // ---- String arm: matched by literal tokens, before the generic arm ----
    ($(#[$attr:meta])* $vis:vis $name:ident, String) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Dynamic<$crate::__private::String>));
        $crate::__sg_newtype_len!($name);
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
        $crate::__sg_newtype_len!($name);
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
                    ::core::result::Result::Ok(Self(
                        <$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_hex(s)?,
                    ))
                }
            }
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

    // ---- explicit generic arm: caller opts in to the reduced API ----
    //
    // `String` and `Vec<u8>` above are matched as literal tokens, so a type
    // alias (`type MyStr = String`) does not reach them. Rather than let such
    // an input fall through and silently lose the shaped API, the fallback
    // requires the `generic` marker; anything else hits the catch-all below.
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty) => {
        $crate::__sg_newtype_base!($(#[$attr])* $vis $name($crate::Dynamic<$inner>));
        $crate::__sg_dynamic_ctor!($name, $inner);
    };

    // ---- catch-all: unrecognised inner type ----
    //
    // Uses `$($rest:tt)+` rather than `$inner:ty` so it can never itself
    // hard-error on a malformed tail; the message names what was written.
    ($(#[$attr:meta])* $vis:vis $name:ident, $($rest:tt)+) => {
        ::core::compile_error!(::core::concat!(
            "dynamic_newtype!: `",
            ::core::stringify!($($rest)+),
            "` is not one of the shaped inner types. `String` and `Vec<u8>` are \
             matched as literal tokens, so a type alias (e.g. `type MyStr = String`) \
             or a fully-qualified path (e.g. `std::string::String`) does NOT match \
             them. Write `String` or `Vec<u8>` literally to get the full API for \
             that shape, or write `generic <type>` to accept the reduced API \
             (RevealSecret, RevealSecretMut, Debug, Zeroize, and `new`) on purpose."
        ));
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
