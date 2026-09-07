//! `dynamic_newtype!` — nominal newtype over `Dynamic<T>`.
//!
//! Ships in 0.9.0. Design record: `docs/nominal_newtypes.md`.

/// Creates a distinct nominal type wrapping [`Dynamic<T>`](crate::Dynamic).
///
/// Mirrors [`dynamic_alias!`](crate::dynamic_alias) syntax, but generates a
/// `struct` rather than a `type` alias: two `dynamic_newtype!` types over the
/// same inner type are **not** interchangeable.
///
/// # Syntax
///
/// ```text
/// dynamic_newtype!(pub Name, String);                    // shaped: full String API
/// dynamic_newtype!(pub Name, Vec<u8>);                   // shaped: full byte API
/// dynamic_newtype!(pub Name, generic T);                 // reduced API, opted into
/// dynamic_newtype!(pub(crate) Name, String);             // crate-visible
/// dynamic_newtype!(Name, String);                        // private
/// dynamic_newtype!(pub Name, String, "doc string");      // with custom doc
/// dynamic_newtype!(pub Name, String, derive: [ConstantTimeEq]);
/// dynamic_newtype!(pub Name, String, "doc", derive: [ConstantTimeEq]);
/// ```
///
/// Supported `derive:` options are `ConstantTimeEq`, `Deserialize`, `FromWrapper`, `IntoWrapper`, and `WrapperAccess` (= both directions);
/// `Clone` and `Serialize` are deliberately absent — see
/// [`fixed_newtype!`](crate::fixed_newtype) for the reasoning and the
/// hand-written pattern, which applies identically here.
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
///
/// # Implementation Notes
///
/// The generated type is `#[repr(transparent)]` over the wrapper and delegates
/// through `#[inline]` methods, so it costs nothing at runtime.
///
/// Unlike [`fixed_newtype!`](crate::fixed_newtype) there is **no zero-size
/// guard** — a `Dynamic` is pointer-sized whatever it holds, so the check
/// would be meaningless. Validate expected lengths in your own tests.
///
/// **Do not add your own `Drop` impl.** None is needed: the wrapped
/// [`Dynamic`](crate::Dynamic) still runs its own, so zeroization is
/// unaffected. Adding one makes the inner field unmovable (**E0509**) and
/// silently costs you [`into_inner`](crate::RevealSecret::into_inner).
///
/// # Security
///
/// Generated types inherit every [`Dynamic`](crate::Dynamic) guarantee:
/// zeroize on drop including spare capacity, `Debug` that always prints
/// `[REDACTED]`, and access only through
/// [`RevealSecret`](crate::RevealSecret) /
/// [`RevealSecretMut`](crate::RevealSecretMut). There is no `Deref`, so a
/// generated newtype is not coercible to its wrapper — which is what keeps the
/// nominal separation total rather than by-value-only.
///
/// **Nominal separation guards against mistakes, not intent** — but nothing is
/// generated that would undo it by accident. There is no `From<Wrapper>` and
/// no `Deref`, so an alias-typed value cannot flow into a newtype through
/// `.into()`, and `&Newtype` never coerces to `&Wrapper` at a call site. By
/// default the only way material enters or leaves is the 3-tier access API —
/// a `with_secret` round trip — which is explicit and shows up in the audit
/// sweep. Base-wrapper access is opt-in, per newtype, and **split by
/// direction**: `derive: [FromWrapper]` adds `from_wrapper` (a base value
/// *enters* this role), `derive: [IntoWrapper]` adds `as_wrapper`,
/// `as_wrapper_mut`, and `into_wrapper` (material *leaves* this role toward
/// the base type), and `derive: [WrapperAccess]` is shorthand for both.
///
/// These cross a different wall from `into_inner`. A newtype has two:
///
/// | Wall | Going in | Going out |
/// |---|---|---|
/// | Contents (the wrapper's protection) | `new`, `From<&str>` / `From<&[u8]>` | `with_secret`, `expose_secret`, `into_inner` |
/// | Role (the nominal label) | `from_wrapper` | `as_wrapper`, `as_wrapper_mut`, `into_wrapper` |
///
/// `into_inner` leaves the protection: the [`InnerSecret`](crate::InnerSecret)
/// it returns derefs, so the contents are in the caller's hands (tier 3 of
/// the access model, audited). `into_wrapper` only removes the label: the
/// result is still a `Dynamic`, still unreadable without `with_secret`. The
/// role row exists so that dropping a label never forces opening the
/// contents — without it, reaching base-typed code costs an `into_inner` plus
/// a rebuild, a reveal the job never needed.
///
/// **Which direction is safe depends on the pool.** In a mixed tree the base
/// type is not raw material: every plain alias sharing it *is* that type, so
/// a directional token connects this role to all of them at once.
/// `FromWrapper` lets anything in the pool become this role — the source never
/// opts in, because the source is just the base type — so a type that guards
/// a boundary must never take it. `IntoWrapper` lets this role become anything
/// in the pool, which is safe only when the role is no more sensitive than
/// the least-sensitive alias sharing its base; on a secret role it is an
/// explicit, greppable downgrade, not a neutral operation. The default,
/// neither token, is sufficient more often than it looks. The exposure is
/// largest during a partial migration — the regime real consumers live in —
/// because while most aliases stay plain the base type is a universal donor.
/// Audit these methods the way you audit `expose_secret()`.
///
/// The heap caveats of [`Dynamic`](crate::Dynamic) carry over unchanged: see
/// `SECURITY.md` on realloc residue for `Vec`/`String` growth after wrapping.
///
/// # See also
///
/// - [`dynamic_alias!`](crate::dynamic_alias) — a `type` alias instead, when
///   readability rather than role separation is the goal
/// - [`fixed_newtype!`](crate::fixed_newtype) — stack-allocated counterpart,
///   and the reference for the `derive:` rules
/// - [`dynamic_generic_alias!`](crate::dynamic_generic_alias) — one name
///   across several inner types
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
    ($(#[$attr:meta])* $vis:vis $name:ident, String, $doc:literal, derive: [$($opt:ident),* $(,)?]) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, String, derive: [$($opt),*]);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, String, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, String, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, Vec<u8>, $doc:literal, derive: [$($opt:ident),* $(,)?]) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, Vec<u8>, derive: [$($opt),*]);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, Vec<u8>, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, Vec<u8>, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty, $doc:literal, derive: [$($opt:ident),* $(,)?]) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, generic $inner, derive: [$($opt),*]);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty, $doc:literal) => {
        $crate::dynamic_newtype!($(#[$attr])* #[doc = $doc] $vis $name, generic $inner, derive: []);
    };

    // ---- String arm: matched by literal tokens, before the generic arm ----
    ($(#[$attr:meta])* $vis:vis $name:ident, String) => {
        $crate::dynamic_newtype!($(#[$attr])* $vis $name, String, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, String, derive: [$($opt:ident),* $(,)?]) => {
        $crate::__sg_newtype_base!(
            $(#[$attr])* $vis $name($crate::Dynamic<$crate::__private::String>), derive: [$($opt),*]
        );
        $crate::__sg_newtype_len!($name);
        $crate::__sg_dynamic_ctor!(@into $name, $crate::__private::String);

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
        $crate::dynamic_newtype!($(#[$attr])* $vis $name, Vec<u8>, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, Vec<u8>, derive: [$($opt:ident),* $(,)?]) => {
        $crate::__sg_newtype_base!(
            $(#[$attr])* $vis $name($crate::Dynamic<$crate::__private::Vec<u8>>), derive: [$($opt),*]
        );
        $crate::__sg_newtype_len!($name);
        $crate::__sg_dynamic_ctor!(@into $name, $crate::__private::Vec<u8>);

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

                /// Generates `len` bytes from a caller-supplied CSPRNG.
                #[inline]
                pub fn from_rng<R>(len: usize, rng: &mut R) -> ::core::result::Result<Self, R::Error>
                where
                    R: $crate::__private::TryRng + $crate::__private::TryCryptoRng,
                {
                    ::core::result::Result::Ok(Self(
                        <$crate::Dynamic<$crate::__private::Vec<u8>>>::from_rng(len, rng)?,
                    ))
                }
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

        $crate::__sg_if_base32! {
            impl $name {
                /// Constant-time Base32 decode into this secret type.
                #[inline]
                pub fn try_from_base32(s: &str) -> ::core::result::Result<Self, $crate::Base32Error> {
                    ::core::result::Result::Ok(Self(
                        <$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_base32(s)?,
                    ))
                }
            }
            impl $crate::ToBase32 for $name {
                #[inline]
                fn to_base32(&self) -> $crate::__private::String {
                    $crate::ToBase32::to_base32(&self.0)
                }
                #[inline]
                fn to_base32_zeroizing(&self) -> $crate::EncodedSecret {
                    $crate::ToBase32::to_base32_zeroizing(&self.0)
                }
            }
        }

        $crate::__sg_if_base64! {
            impl $name {
                /// Constant-time Base64url decode into this secret type.
                #[inline]
                pub fn try_from_base64url(s: &str) -> ::core::result::Result<Self, $crate::Base64Error> {
                    ::core::result::Result::Ok(Self(
                        <$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_base64url(s)?,
                    ))
                }
            }
            impl $crate::ToBase64Url for $name {
                #[inline]
                fn to_base64url(&self) -> $crate::__private::String {
                    $crate::ToBase64Url::to_base64url(&self.0)
                }
                #[inline]
                fn to_base64url_zeroizing(&self) -> $crate::EncodedSecret {
                    $crate::ToBase64Url::to_base64url_zeroizing(&self.0)
                }
            }
        }

        $crate::__sg_if_bech32! {
            impl $name {
                /// HRP-validated Bech32 decode into this secret type.
                #[inline]
                pub fn try_from_bech32(s: &str, expected_hrp: &str)
                    -> ::core::result::Result<Self, $crate::Bech32Error> {
                    ::core::result::Result::Ok(Self(
                        <$crate::Dynamic<$crate::__private::Vec<u8>>>::try_from_bech32(s, expected_hrp)?,
                    ))
                }
            }
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
        }

        $crate::__sg_if_bech32m! {
            impl $crate::ToBech32m for $name {
                #[inline]
                fn try_to_bech32m(
                    &self,
                    hrp: &str,
                ) -> ::core::result::Result<$crate::__private::String, $crate::Bech32Error> {
                    $crate::ToBech32m::try_to_bech32m(&self.0, hrp)
                }
                #[inline]
                fn try_to_bech32m_zeroizing(
                    &self,
                    hrp: &str,
                ) -> ::core::result::Result<$crate::EncodedSecret, $crate::Bech32Error> {
                    $crate::ToBech32m::try_to_bech32m_zeroizing(&self.0, hrp)
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
        $crate::dynamic_newtype!($(#[$attr])* $vis $name, generic $inner, derive: []);
    };
    ($(#[$attr:meta])* $vis:vis $name:ident, generic $inner:ty, derive: [$($opt:ident),* $(,)?]) => {
        $crate::__sg_newtype_base!(
            $(#[$attr])* $vis $name($crate::Dynamic<$inner>), derive: [$($opt),*]
        );
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
    // Shaped arms: accept anything convertible to the inner value, so
    // `Name::new("literal")` and `Name::new(string)` both work — the shape a
    // hand-written `new(impl Into<String>)` has, so call sites need not move.
    (@into $name:ident, $inner:ty) => {
        impl $name {
            /// Creates the secret from any value convertible into the inner type.
            #[inline(always)]
            pub fn new(value: impl ::core::convert::Into<$inner>) -> Self {
                Self(<$crate::Dynamic<$inner>>::new(value.into()))
            }
        }
    };
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
